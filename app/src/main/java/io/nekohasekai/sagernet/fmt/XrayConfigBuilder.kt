package io.nekohasekai.sagernet.fmt

import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.database.SagerDatabase
import io.nekohasekai.sagernet.fmt.http.HttpBean
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean
import io.nekohasekai.sagernet.fmt.snell.SnellBean
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean
import io.nekohasekai.sagernet.fmt.tuic.TuicBean
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean
import io.nekohasekai.sagernet.fmt.v2ray.isTLS
import io.nekohasekai.sagernet.fmt.v2ray.normalizeXhttpMode
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean
import moe.matsuri.nb4a.proxy.config.ConfigBean
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.mkPort
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Xray-core 配置构建器
 * 将 OwnXray 的 ProxyEntity 实体转译为标准的 Xray JSON 配置，
 * 原生支持 VLESS (Vision / REALITY)、XHTTP 传输、VMess、Trojan、Shadowsocks 等官方协议栈；
 * 支持单节点快速测速（零端口冲突）、多节点策略分流、自定义配置及 TUN 虚拟网卡。
 */
object XrayConfigBuilder {

    fun hasGeoSite(): Boolean {
        return runCatching {
            val noBackup = SagerNet.application.noBackupFilesDir
            val files = SagerNet.application.filesDir
            File(noBackup, "geosite.dat").exists() ||
            File(noBackup, "GeoSite.dat").exists() ||
            File(files, "geosite.dat").exists() ||
            File(files, "GeoSite.dat").exists()
        }.getOrDefault(false)
    }

    fun hasGeoIP(): Boolean {
        return runCatching {
            val noBackup = SagerNet.application.noBackupFilesDir
            val files = SagerNet.application.filesDir
            File(noBackup, "geoip.dat").exists() ||
            File(noBackup, "GeoIP.dat").exists() ||
            File(noBackup, "Country.mmdb").exists() ||
            File(noBackup, "country.mmdb").exists() ||
            File(files, "geoip.dat").exists() ||
            File(files, "GeoIP.dat").exists()
        }.getOrDefault(false)
    }

    fun build(profile: ProxyEntity, forTest: Boolean = false): ConfigBuildResult {
        // 1. 如果是 TYPE_CONFIG (自定义配置 / 完整 Xray 配置 / Sing-box 配置)
        if (profile.type == ProxyEntity.TYPE_CONFIG) {
            val bean = profile.requireBean() as? ConfigBean
            if (bean != null && bean.config.isNotBlank()) {
                val patched = patchRawConfig(bean.config, forTest = forTest)
                val nodeName = profile.displayName().ifBlank { "CONFIG" }
                return ConfigBuildResult(
                    config = patched,
                    externalIndex = emptyList(),
                    mainEntId = profile.id,
                    trafficMap = mapOf(nodeName to listOf(profile)),
                    profileTagMap = mapOf(profile.id to nodeName),
                    selectorGroupId = 0L
                )
            }
        }

        // 2. 构造主节点与同组节点
        val nodeName = profile.displayName().ifBlank { "PROXY_NODE" }
        val outbounds = mutableListOf<JSONObject>()
        val trafficMap = mutableMapOf<String, List<ProxyEntity>>()
        val profileTagMap = mutableMapOf<Long, String>()
        val proxyNames = mutableListOf<String>()

        val activeOutbound = buildSingleOutbound("proxy", profile)
        outbounds.add(activeOutbound)
        trafficMap[nodeName] = listOf(profile)
        profileTagMap[profile.id] = "proxy"
        proxyNames.add(nodeName)

        // 若不是单节点测速，且存在分组，则载入该分组下其余可用节点，供切换与测速使用
        if (!forTest && profile.groupId > 0) {
            try {
                val groupEntities = SagerDatabase.proxyDao.getByGroup(profile.groupId)
                for (ent in groupEntities) {
                    if (ent.id == profile.id) continue
                    val name = ent.displayName().ifBlank { "Node-" }
                    val uniqueTag = "proxy-${ent.id}"
                    try {
                        val ob = buildSingleOutbound(uniqueTag, ent)
                        outbounds.add(ob)
                        trafficMap[name] = listOf(ent)
                        profileTagMap[ent.id] = uniqueTag
                        proxyNames.add(name)
                    } catch (_: Exception) {
                    }
                }
            } catch (_: Exception) {
            }
        }

        val jsonString = buildFullXrayJson(outbounds, forTest = forTest)

        return ConfigBuildResult(
            config = jsonString,
            externalIndex = emptyList(),
            mainEntId = profile.id,
            trafficMap = trafficMap,
            profileTagMap = profileTagMap,
            selectorGroupId = 0L
        )
    }

    fun patchRawConfig(rawConfig: String, forTest: Boolean = false): String {
        val trimmed = rawConfig.trim()
        if (trimmed.startsWith("{")) {
            try {
                val json = JSONObject(trimmed)
                if (forTest) {
                    // 移除系统级监听与网卡，避免冲突
                    json.remove("inbounds")
                    val testInbound = JSONObject().apply {
                        put("tag", "test-in")
                        put("port", mkPort())
                        put("listen", "127.0.0.1")
                        put("protocol", "socks")
                        put("settings", JSONObject().apply {
                            put("auth", "noauth")
                            put("udp", true)
                        })
                    }
                    json.put("inbounds", JSONArray().put(testInbound))
                }
                return json.toString(2)
            } catch (_: Exception) {
            }
        }
        return rawConfig
    }

    fun buildSingleOutbound(tag: String, profile: ProxyEntity): JSONObject {
        val bean = profile.requireBean()
        val outbound = JSONObject()
        outbound.put("tag", tag)

        when (bean) {
            is StandardV2RayBean -> {
                val isVless = (bean is VMessBean && bean.alterId == -1)
                outbound.put("protocol", if (isVless) "vless" else "vmess")

                val vnextUser = JSONObject().apply {
                    put("id", bean.uuid)
                    if (isVless) {
                        put("encryption", "none")
                        val flow = bean.encryption
                        if (!flow.isNullOrBlank() && (flow.contains("vision") || flow.contains("xtls"))) {
                            put("flow", flow)
                        }
                    } else {
                        val alterId = (bean as? VMessBean)?.alterId ?: 0
                        put("alterId", alterId)
                        put("security", if (bean.encryption.isNullOrBlank()) "auto" else bean.encryption)
                    }
                }

                val vnextServer = JSONObject().apply {
                    put("address", bean.serverAddress)
                    put("port", bean.serverPort)
                    put("users", JSONArray().put(vnextUser))
                }
                outbound.put("settings", JSONObject().put("vnext", JSONArray().put(vnextServer)))

                // streamSettings
                val stream = JSONObject()
                val netType = bean.type?.lowercase() ?: "tcp"
                stream.put("network", when (netType) {
                    "ws", "websocket" -> "ws"
                    "grpc" -> "grpc"
                    "xhttp", "splithttp" -> "xhttp"
                    "kcp", "mkcp" -> "kcp"
                    "http", "h2" -> "http"
                    else -> "tcp"
                })

                // security: reality, tls, none
                val isReality = (bean.security == "reality" || !bean.realityPubKey.isNullOrBlank())
                if (isReality) {
                    stream.put("security", "reality")
                    val realitySettings = JSONObject().apply {
                        put("show", false)
                        put("fingerprint", if (bean.utlsFingerprint.isNullOrBlank()) "chrome" else bean.utlsFingerprint)
                        put("serverName", if (bean.sni.isNullOrBlank()) bean.serverAddress else bean.sni)
                        put("publicKey", bean.realityPubKey ?: "")
                        put("shortId", bean.realityShortId ?: "")
                        put("spiderX", "/")
                    }
                    stream.put("realitySettings", realitySettings)
                } else if (bean.security == "tls" || bean.isTLS()) {
                    stream.put("security", "tls")
                    val tlsSettings = JSONObject().apply {
                        put("serverName", if (bean.sni.isNullOrBlank()) bean.serverAddress else bean.sni)
                        put("allowInsecure", bean.allowInsecure == true)
                        put("fingerprint", if (bean.utlsFingerprint.isNullOrBlank()) "chrome" else bean.utlsFingerprint)
                        if (!bean.alpn.isNullOrBlank()) {
                            val alpnArray = JSONArray()
                            bean.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }.forEach { alpnArray.put(it) }
                            if (alpnArray.length() > 0) put("alpn", alpnArray)
                        }
                    }
                    stream.put("tlsSettings", tlsSettings)
                } else {
                    stream.put("security", "none")
                }

                // Transport settings
                when (stream.getString("network")) {
                    "ws" -> {
                        val ws = JSONObject().apply {
                            put("path", if (bean.path.isNullOrBlank()) "/" else bean.path)
                            if (!bean.host.isNullOrBlank()) {
                                put("headers", JSONObject().put("Host", bean.host))
                            }
                        }
                        stream.put("wsSettings", ws)
                    }
                    "grpc" -> {
                        val grpc = JSONObject().apply {
                            put("serviceName", bean.path ?: "")
                            put("multiMode", true)
                        }
                        stream.put("grpcSettings", grpc)
                    }
                    "xhttp" -> {
                        val xh = JSONObject().apply {
                            put("mode", normalizeXhttpMode(bean.xhttpMode))
                            put("path", if (bean.path.isNullOrBlank()) "/" else bean.path)
                            if (!bean.host.isNullOrBlank()) {
                                put("host", bean.host)
                            }
                            if (!bean.xhttpExtra.isNullOrBlank()) {
                                try {
                                    put("extra", JSONObject(bean.xhttpExtra))
                                } catch (_: Exception) {}
                            }
                        }
                        stream.put("xhttpSettings", xh)
                    }
                    "kcp" -> {
                        val kcp = JSONObject().apply {
                            put("header", JSONObject().put("type", if (bean.headerType.isNullOrBlank()) "none" else bean.headerType))
                            put("seed", bean.mKcpSeed ?: "")
                        }
                        stream.put("kcpSettings", kcp)
                    }
                    "http" -> {
                        val http = JSONObject().apply {
                            put("path", if (bean.path.isNullOrBlank()) "/" else bean.path)
                            if (!bean.host.isNullOrBlank()) {
                                val hostArray = JSONArray()
                                bean.host.split(",").map { it.trim() }.filter { it.isNotBlank() }.forEach { hostArray.put(it) }
                                put("host", hostArray)
                            }
                        }
                        stream.put("httpSettings", http)
                    }
                }

                outbound.put("streamSettings", stream)
            }
            is TrojanBean -> {
                outbound.put("protocol", "trojan")
                val srv = JSONObject().apply {
                    put("address", bean.serverAddress)
                    put("port", bean.serverPort)
                    put("password", bean.password)
                }
                outbound.put("settings", JSONObject().put("servers", JSONArray().put(srv)))

                val stream = JSONObject()
                val netType = bean.type?.lowercase() ?: "tcp"
                stream.put("network", when (netType) {
                    "ws", "websocket" -> "ws"
                    "grpc" -> "grpc"
                    else -> "tcp"
                })
                stream.put("security", "tls")
                val tlsSettings = JSONObject().apply {
                    put("serverName", if (bean.sni.isNullOrBlank()) bean.serverAddress else bean.sni)
                    put("allowInsecure", bean.allowInsecure == true)
                    if (!bean.alpn.isNullOrBlank()) {
                        val alpnArray = JSONArray()
                        bean.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }.forEach { alpnArray.put(it) }
                        if (alpnArray.length() > 0) put("alpn", alpnArray)
                    }
                }
                stream.put("tlsSettings", tlsSettings)
                if (stream.getString("network") == "ws") {
                    val ws = JSONObject().apply {
                        put("path", if (bean.path.isNullOrBlank()) "/" else bean.path)
                        if (!bean.host.isNullOrBlank()) {
                            put("headers", JSONObject().put("Host", bean.host))
                        }
                    }
                    stream.put("wsSettings", ws)
                } else if (stream.getString("network") == "grpc") {
                    stream.put("grpcSettings", JSONObject().apply {
                        put("serviceName", bean.path ?: "")
                    })
                }
                outbound.put("streamSettings", stream)
            }
            is ShadowsocksBean -> {
                outbound.put("protocol", "shadowsocks")
                val srv = JSONObject().apply {
                    put("address", bean.serverAddress)
                    put("port", bean.serverPort)
                    put("method", bean.method)
                    put("password", bean.password)
                    put("uot", true)
                }
                outbound.put("settings", JSONObject().put("servers", JSONArray().put(srv)))
            }
            is SOCKSBean -> {
                outbound.put("protocol", "socks")
                val srv = JSONObject().apply {
                    put("address", bean.serverAddress)
                    put("port", bean.serverPort)
                }
                outbound.put("settings", JSONObject().put("servers", JSONArray().put(srv)))
            }
            is HttpBean -> {
                outbound.put("protocol", "http")
                val srv = JSONObject().apply {
                    put("address", bean.serverAddress)
                    put("port", bean.serverPort)
                }
                outbound.put("settings", JSONObject().put("servers", JSONArray().put(srv)))
            }
            else -> {
                // Fallback direct outbound
                outbound.put("protocol", "freedom")
                outbound.put("settings", JSONObject())
            }
        }

        return outbound
    }

    fun buildFullXrayJson(outbounds: List<JSONObject>, forTest: Boolean = false): String {
        val root = JSONObject()
        root.put("core", "xray")

        // 1. log
        root.put("log", JSONObject().apply {
            put("loglevel", if (forTest) "none" else "warning")
        })

        // 2. inbounds
        val inbounds = JSONArray()
        if (forTest) {
            val testIn = JSONObject().apply {
                put("tag", "test-in")
                put("port", mkPort())
                put("listen", "127.0.0.1")
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
            }
            inbounds.put(testIn)
        } else {
            // SOCKS inbound on 2080
            inbounds.put(JSONObject().apply {
                put("tag", "mixed-in")
                put("port", 2080)
                put("listen", "127.0.0.1")
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                })
            })
            // HTTP inbound on 2081
            inbounds.put(JSONObject().apply {
                put("tag", "http-in")
                put("port", 2081)
                put("listen", "127.0.0.1")
                put("protocol", "http")
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                })
            })
            // Dokodemo-door inbound on 2082 (for TUN redirect)
            inbounds.put(JSONObject().apply {
                put("tag", "dokodemo-in")
                put("port", 2082)
                put("listen", "127.0.0.1")
                put("protocol", "dokodemo-door")
                put("settings", JSONObject().apply {
                    put("network", "tcp,udp")
                    put("followRedirect", true)
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                })
            })
        }
        root.put("inbounds", inbounds)

        // 3. outbounds
        val obs = JSONArray()
        for (ob in outbounds) {
            obs.put(ob)
        }
        // Direct
        obs.put(JSONObject().apply {
            put("tag", "direct")
            put("protocol", "freedom")
            put("settings", JSONObject().apply {
                put("domainStrategy", "UseIP")
            })
        })
        // Block
        obs.put(JSONObject().apply {
            put("tag", "block")
            put("protocol", "blackhole")
            put("settings", JSONObject().apply {
                put("response", JSONObject().put("type", "none"))
            })
        })
        root.put("outbounds", obs)

        // 4. routing
        val routing = JSONObject()
        routing.put("domainStrategy", "IPIfNonMatch")
        val rules = JSONArray()

        if (!forTest) {
            if (DataStore.bypassLan) {
                rules.put(JSONObject().apply {
                    put("type", "field")
                    put("outboundTag", "direct")
                    put("ip", JSONArray().put("geoip:private"))
                })
            }
            try {
                val dbRules = SagerDatabase.rulesDao.enabledRules()
                for (r in dbRules) {
                    val target = when (r.outbound) {
                        -1L -> "direct"
                        -2L -> "block"
                        else -> "proxy"
                    }
                    val ruleObj = JSONObject().apply {
                        put("type", "field")
                        put("outboundTag", target)
                    }
                    var hasCondition = false
                    if (r.domains.isNotBlank()) {
                        val domainArray = JSONArray()
                        for (d in r.domains.split("\n")) {
                            val td = d.trim()
                            if (td.isBlank()) continue
                            domainArray.put(td)
                        }
                        if (domainArray.length() > 0) {
                            ruleObj.put("domain", domainArray)
                            hasCondition = true
                        }
                    }
                    if (r.ip.isNotBlank()) {
                        val ipArray = JSONArray()
                        for (ip in r.ip.split("\n")) {
                            val tip = ip.trim()
                            if (tip.isBlank()) continue
                            ipArray.put(tip)
                        }
                        if (ipArray.length() > 0) {
                            ruleObj.put("ip", ipArray)
                            hasCondition = true
                        }
                    }
                    if (r.port.isNotBlank()) {
                        val tp = r.port.trim().replace("\n", ",")
                        if (tp.isNotBlank()) {
                            ruleObj.put("port", tp)
                            hasCondition = true
                        }
                    }
                    if (r.network.isNotBlank()) {
                        val tn = r.network.trim().lowercase()
                        if (tn.isNotBlank()) {
                            ruleObj.put("network", tn)
                            hasCondition = true
                        }
                    }
                    if (hasCondition) {
                        rules.put(ruleObj)
                    }
                }
            } catch (e: Throwable) {
                Logs.w(e)
            }
        }
        // Default rule: route all inbounds to proxy
        rules.put(JSONObject().apply {
            put("type", "field")
            put("outboundTag", "proxy")
            put("network", "tcp,udp")
        })
        routing.put("rules", rules)
        root.put("routing", routing)

        // 5. dns
        val dns = JSONObject()
        val dnsServers = JSONArray()
        if (DataStore.remoteDns.isNotBlank()) {
            dnsServers.put(DataStore.remoteDns)
        } else {
            dnsServers.put("https://dns.google/dns-query")
        }
        if (DataStore.directDns.isNotBlank()) {
            val directDnsObj = JSONObject().apply {
                put("address", DataStore.directDns)
                put("domains", JSONArray().put("geosite:cn"))
                put("expectIPs", JSONArray().put("geoip:cn"))
            }
            dnsServers.put(directDnsObj)
        }
        dnsServers.put("1.1.1.1")
        dnsServers.put("localhost")
        dns.put("servers", dnsServers)
        root.put("dns", dns)

        // 6. stats & policy
        root.put("stats", JSONObject())
        root.put("policy", JSONObject().apply {
            put("levels", JSONObject().put("0", JSONObject().apply {
                put("statsUserUplink", true)
                put("statsUserDownlink", true)
            }))
            put("system", JSONObject().apply {
                put("statsOutboundUplink", true)
                put("statsOutboundDownlink", true)
            })
        })

        return root.toString(2)
    }
}
