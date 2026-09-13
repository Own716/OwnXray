package libcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_tun"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var (
	mihomoMux    sync.Mutex
	activeMihomo *BoxInstance
)

func init() {
	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) {
			if intfBox != nil {
				intfBox.AutoDetectInterfaceControl(int32(fd))
			}
		})
	}
}

func NewMihomoInstance(configYaml string, localTransport LocalDNSTransport) (*BoxInstance, error) {
	return newMihomoInstance(configYaml, localTransport, true)
}

func NewTestMihomoInstance(configYaml string, localTransport LocalDNSTransport) (*BoxInstance, error) {
	return newMihomoInstance(configYaml, localTransport, false)
}

func newMihomoInstance(configYaml string, localTransport LocalDNSTransport, platformLog bool) (*BoxInstance, error) {
	diagnosticID := boxInstanceSequence.Add(1)

	cfg, err := executor.ParseWithBytes([]byte(configYaml))
	if err != nil {
		return nil, fmt.Errorf("parse mihomo config error: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	isTest := !platformLog

	b := &BoxInstance{
		cancel:       cancel,
		diagnosticID: diagnosticID,
		isURLTest:    isTest,
		isMihomo:     true,
		testProxies:  cfg.Proxies,
	}

	if len(cfg.Proxies) > 0 {
		for name := range cfg.Proxies {
			if name != "DIRECT" && name != "REJECT" {
				b.diagnosticTag = name
				break
			}
		}
	}

	if isTest {
		// 独立测速实例 (TestInstance / URLTest)：
		// 1. 绝不调用 executor.ApplyConfig，绝不绑定本地入站端口（如 mixed-port 2080），避免端口占用；
		// 2. 绝不覆盖主进程或 VPN 的全局 Tunnel 与 Listeners，完全支持多并发测速；
		// 3. 绝不在 close 时调用 executor.Shutdown()，绝不打断正在运行的 VPN 代理或并发连接，
		//    彻底杜绝由于全局 Shutdown 导致的 "EOF" 与未捕获 panic / SIGABRT 崩溃。
		b.startBox = func() error {
			return nil
		}

		b.closeBox = func() error {
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
			tCtx, testCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
			defer testCancel()

			var targetProxy C.Proxy
			if len(b.testProxies) > 0 {
				targetProxy = b.testProxies[b.diagnosticTag]
				if targetProxy == nil {
					for name, p := range b.testProxies {
						if name != "DIRECT" && name != "REJECT" {
							targetProxy = p
							break
						}
					}
				}
			}
			if targetProxy == nil {
				proxies := tunnel.Tunnel.Proxies()
				targetProxy = proxies[b.diagnosticTag]
				if targetProxy == nil {
					targetProxy = proxies["PROXY"]
				}
			}

			if targetProxy == nil {
				return -1, errors.New("no valid outbound proxy found for url test")
			}

			delay, err := targetProxy.URLTest(tCtx, testLink, nil)
			if err != nil {
				fallback := getFallbackLink(testLink)
				fbDelay, fbErr := targetProxy.URLTest(tCtx, fallback, nil)
				if fbErr == nil {
					return int32(fbDelay), nil
				}
				return -1, err
			}
			return int32(delay), nil
		}

		return b, nil
	}

	// 主运行实例 (VPN/ProxyService)
	var tunListener *sing_tun.Listener

	b.startBox = func() error {
		mihomoMux.Lock()
		defer mihomoMux.Unlock()

		stack := C.TunGvisor
		mtu := uint32(9000)
		if cfg.General != nil {
			if cfg.General.Tun.Stack != 0 {
				stack = cfg.General.Tun.Stack
			}
			if cfg.General.Tun.MTU > 0 {
				mtu = cfg.General.Tun.MTU
			}
			cfg.General.Tun.Enable = false
		}
		executor.ApplyConfig(cfg, true)

		if intfBox != nil {
			tunFd, err := intfBox.OpenTun("{}", "{}")
			if err != nil || tunFd < 0 {
				return errors.New("failed to open Android TUN fd")
			}

			tunOptions := LC.Tun{
				Enable:              true,
				Device:              "tun0",
				Stack:               stack,
				DNSHijack:           []string{"172.19.0.2:53", "0.0.0.0:53"},
				AutoRoute:           false,
				AutoDetectInterface: false,
				Inet4Address:        []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
				Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
				MTU:                 mtu,
				FileDescriptor:      int(tunFd),
			}

			l, err := sing_tun.New(tunOptions, tunnel.Tunnel)
			if err != nil {
				return fmt.Errorf("create sing_tun listener failed: %w", err)
			}
			tunListener = l
		}

		activeMihomo = b
		return nil
	}

	b.closeBox = func() error {
		mihomoMux.Lock()
		defer mihomoMux.Unlock()

		if tunListener != nil {
			_ = tunListener.Close()
			tunListener = nil
		}
		if activeMihomo == b {
			executor.Shutdown()
			activeMihomo = nil
		}
		cancel()
		return nil
	}

	b.selectOutboundBox = func(tag string) bool {
		for _, p := range tunnel.Tunnel.Proxies() {
			if group, ok := p.(outboundgroup.SelectAble); ok {
				if err := group.Set(tag); err == nil {
					return true
				}
			}
		}
		return false
	}

	b.queryStatsBox = func(tag, direct string) int64 {
		snap := statistic.DefaultManager.Snapshot()
		if direct == "uplink" || direct == "upload" {
			return snap.UploadTotal
		}
		return snap.DownloadTotal
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
		tCtx, testCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Millisecond)
		defer testCancel()

		proxies := tunnel.Tunnel.Proxies()
		targetProxy := proxies[b.diagnosticTag]
		if targetProxy == nil {
			targetProxy = proxies["PROXY"]
		}
		if targetProxy == nil {
			for _, p := range proxies {
				if p.Type() != C.Direct && p.Type() != C.Reject && p.Type() != C.Relay {
					targetProxy = p
					break
				}
			}
		}

		if targetProxy == nil {
			return -1, errors.New("no valid outbound proxy found for url test")
		}

		delay, err := targetProxy.URLTest(tCtx, testLink, nil)
		if err != nil {
			fallback := getFallbackLink(testLink)
			fbDelay, fbErr := targetProxy.URLTest(tCtx, fallback, nil)
			if fbErr == nil {
				return int32(fbDelay), nil
			}
			return -1, err
		}
		return int32(delay), nil
	}

	return b, nil
}

func dialMihomo(ctx context.Context, tag string, network, addr string) (net.Conn, error) {
	proxies := tunnel.Tunnel.Proxies()
	targetProxy := proxies[tag]
	if targetProxy == nil {
		targetProxy = proxies["PROXY"]
	}
	if targetProxy == nil {
		for _, p := range proxies {
			if p.Type() != C.Direct && p.Type() != C.Reject && p.Type() != C.Relay {
				targetProxy = p
				break
			}
		}
	}
	if targetProxy == nil {
		return nil, errors.New("no valid mihomo outbound proxy found")
	}

	m := &C.Metadata{
		NetWork: C.TCP,
	}
	if network == "udp" {
		m.NetWork = C.UDP
	}
	if err := m.SetRemoteAddress(addr); err != nil {
		return nil, err
	}
	return targetProxy.DialContext(ctx, m)
}

