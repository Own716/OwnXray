package libcore

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
)

var (
	xrayMux    sync.Mutex
	activeXray *BoxInstance
)

func init() {
	_ = internet.RegisterDialerController(func(network, address string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) {
			if intfBox != nil {
				intfBox.AutoDetectInterfaceControl(int32(fd))
			}
		})
	})
}

func NewXrayInstance(configJson string, localTransport LocalDNSTransport) (*BoxInstance, error) {
	return newXrayInstance(configJson, localTransport, true)
}

func NewTestXrayInstance(configJson string, localTransport LocalDNSTransport) (*BoxInstance, error) {
	return newXrayInstance(configJson, localTransport, false)
}

func newXrayInstance(configJson string, localTransport LocalDNSTransport, platformLog bool) (*BoxInstance, error) {
	diagnosticID := boxInstanceSequence.Add(1)

	server, err := core.StartInstance("jsonv4", []byte(configJson))
	if err != nil {
		return nil, fmt.Errorf("start xray instance failed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	isTest := !platformLog

	b := &BoxInstance{
		cancel:       cancel,
		diagnosticID: diagnosticID,
		isURLTest:    isTest,
		isXray:       true,
	}

	if isTest {
		b.startBox = func() error {
			return nil
		}

		b.closeBox = func() error {
			defer func() { _ = recover() }()
			_ = server.Close()
			cancel()
			return nil
		}

		b.urlTestBox = func(link string, timeout int32) (latency int32, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("urltest panic: %v", r)
					latency = -1
				}
			}()

			testLink := link
			if testLink == "" {
				testLink = defaultFallbackURL
			}

			parsedURL, parseErr := url.Parse(testLink)
			if parseErr != nil {
				return -1, fmt.Errorf("invalid test url: %w", parseErr)
			}

			targetPort := parsedURL.Port()
			if targetPort == "" {
				if strings.EqualFold(parsedURL.Scheme, "https") {
					targetPort = "443"
				} else {
					targetPort = "80"
				}
			}

			tCtx, testCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
			defer testCancel()

			httpClient := &http.Client{
				Timeout: time.Duration(timeout) * time.Millisecond,
				Transport: &http.Transport{
					DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
						h, pStr, sErr := net.SplitHostPort(addr)
						if sErr != nil {
							h = addr
							pStr = targetPort
						}
						p, _ := strconv.Atoi(pStr)
						dest := xraynet.TCPDestination(xraynet.ParseAddress(h), xraynet.Port(p))
						return core.Dial(dialCtx, server, dest)
					},
					ForceAttemptHTTP2:   true,
					DisableKeepAlives:   true,
					TLSHandshakeTimeout: time.Duration(timeout) * time.Millisecond,
				},
			}

			started := time.Now()
			req, rErr := http.NewRequestWithContext(tCtx, http.MethodHead, testLink, nil)
			if rErr != nil {
				return -1, rErr
			}
			req.Header.Set("User-Agent", browserUserAgent)

			resp, hErr := httpClient.Do(req)
			if hErr != nil {
				fbURL := defaultFallbackURL
				fbReq, fbReqErr := http.NewRequestWithContext(tCtx, http.MethodHead, fbURL, nil)
				if fbReqErr == nil {
					fbReq.Header.Set("User-Agent", browserUserAgent)
					fbStarted := time.Now()
					fbResp, fbErr := httpClient.Do(fbReq)
					if fbErr == nil {
						_ = fbResp.Body.Close()
						return int32(time.Since(fbStarted).Milliseconds()), nil
					}
				}
				return -1, hErr
			}
			_ = resp.Body.Close()
			return int32(time.Since(started).Milliseconds()), nil
		}

		return b, nil
	}

	// 主运行实例 (VPN/ProxyService)
	b.startBox = func() error {
		xrayMux.Lock()
		defer xrayMux.Unlock()

		if intfBox != nil {
			tunFd, err := intfBox.OpenTun("{}", "{}")
			if err != nil || tunFd < 0 {
				log.Println("warn: failed to open Android TUN fd:", err)
			}
		}

		activeXray = b
		return nil
	}

	b.closeBox = func() error {
		xrayMux.Lock()
		defer xrayMux.Unlock()

		if activeXray == b {
			activeXray = nil
		}
		_ = server.Close()
		cancel()
		return nil
	}

	b.queryStatsBox = func(tag, direct string) int64 {
		statsMgr := server.GetFeature(stats.ManagerType())
		if statsMgr == nil {
			return 0
		}
		counterName := fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, direct)
		counter := statsMgr.(stats.Manager).GetCounter(counterName)
		if counter == nil {
			return 0
		}
		return counter.Value()
	}

	return b, nil
}
