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
import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml

/**
 * OwnXray 外部配置解析与转译构建器
 * 将 ProxyEntity 实体及订阅配置转译为标准配置，
 * 完整支持所有协议（VLESS-XHTTP、REALITY、VMess、Trojan、Shadowsocks 等）、
 * 多节点订阅分组、策略组（SELECT / AUTO / FALLBACK）、自定义配置及分流规则。
 */
object MihomoConfigBuilder {

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
        // 1. 如果是 TYPE_CONFIG (自定义配置 / 完整 Clash 配置 / Sing-box 配置)
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

        // 2. 构造或获取节点列表
        val nodeName = profile.displayName().ifBlank { "PROXY_NODE" }
        val proxies = mutableListOf<Map<String, Any?>>()
        val trafficMap = mutableMapOf<String, List<ProxyEntity>>()
        val profileTagMap = mutableMapOf<Long, String>()
        val proxyNames = mutableListOf<String>()

        val activeProxyMap = buildSingleProxy(nodeName, profile)
        proxies.add(activeProxyMap)
        trafficMap[nodeName] = listOf(profile)
        profileTagMap[profile.id] = nodeName
        proxyNames.add(nodeName)

        // 若不是单节点测速，且存在分组，则载入该分组下其余可用节点，供策略组与测速/切换面板使用
        if (!forTest && profile.groupId > 0) {
            try {
                val groupEntities = SagerDatabase.proxyDao.getByGroup(profile.groupId)
                for (ent in groupEntities) {
                    if (ent.id == profile.id) continue
                    val name = ent.displayName().ifBlank { "Node-${ent.id}" }
                    var uniqueName = name
                    var suffix = 2
                    while (proxyNames.contains(uniqueName)) {
                        uniqueName = "$name ($suffix)"
                        suffix++
                    }
                    try {
                        val m = buildSingleProxy(uniqueName, ent)
                        proxies.add(m)
                        trafficMap[uniqueName] = listOf(ent)
                        profileTagMap[ent.id] = uniqueName
                        proxyNames.add(uniqueName)
                    } catch (_: Exception) {
                    }
                }
            } catch (_: Exception) {
            }
        }

        val yamlString = buildFullMihomoYaml(proxies, proxyNames, forTest = forTest)

        return ConfigBuildResult(
            config = yamlString,
            externalIndex = emptyList(),
            mainEntId = profile.id,
            trafficMap = trafficMap,
            profileTagMap = profileTagMap,
            selectorGroupId = 0L
        )
    }

    fun patchRawConfig(rawConfig: String, forTest: Boolean = false): String {
        val trimmed = rawConfig.trim()
        if (trimmed.startsWith("{") && trimmed.contains("\"outbounds\"")) {
            return convertSingBoxConfigToMihomoYaml(trimmed, forTest = forTest)
        }
        if (trimmed.startsWith("{") && trimmed.contains("\"server\"")) {
            try {
                val jsonObj = JSONObject(trimmed)
                val m = convertSingBoxOutboundToMihomo("PROXY_NODE", jsonObj)
                if (m != null) {
                    return buildFullMihomoYaml(listOf(m), listOf("PROXY_NODE"), forTest = forTest)
                }
            } catch (_: Exception) {}
        }
        try {
            val yaml = Yaml()
            val loaded = yaml.load<Any>(rawConfig)
            if (loaded is Map<*, *>) {
                val map = LinkedHashMap<String, Any?>()
                for ((k, v) in loaded) {
                    if (k != null) map[k.toString()] = v
                }
                val tunMap = linkedMapOf<String, Any?>()
                tunMap["enable"] = true
                tunMap["stack"] = when (DataStore.tunImplementation) {
                    0 -> "gvisor"
                    1 -> "system"
                    2 -> "mixed"
                    else -> "gvisor"
                }
                tunMap["device"] = "tun0"
                tunMap["auto-route"] = false
                tunMap["auto-detect-interface"] = false
                tunMap["mtu"] = DataStore.mtu
                tunMap["dns-hijack"] = listOf("172.19.0.2:53", "0.0.0.0:53")
                map["tun"] = tunMap

                map["geox-url"] = mapOf(
                    "geosite" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
                    "geoip" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
                    "mmdb" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
                )
                map["geo-auto-update"] = false

                if (forTest) {
                    map.remove("external-controller")
                    map.remove("mixed-port")
                    map.remove("port")
                    map.remove("socks-port")
                    map.remove("redir-port")
                    map.remove("tproxy-port")
                    tunMap["enable"] = false
                    map["rules"] = listOf("MATCH,DIRECT")
                } else {
                    map["external-controller"] = "127.0.0.1:9090"
                    map["secret"] = ""
                    if (!DataStore.disableMixedInbound) {
                        map["mixed-port"] = DataStore.mixedPort
                    }
                    if (!hasGeoSite()) {
                        val origRules = map["rules"] as? List<*>
                        if (origRules != null) {
                            map["rules"] = origRules.filterNot {
                                it?.toString()?.startsWith("GEOSITE,", ignoreCase = true) == true
                            }
                        }
                    }
                }

                val options = DumperOptions().apply {
                    defaultFlowStyle = DumperOptions.FlowStyle.BLOCK
                    isPrettyFlow = true
                }
                return Yaml(options).dump(map)
            }
        } catch (_: Exception) {
        }
        return rawConfig
    }

    fun convertSingBoxConfigToMihomoYaml(configJson: String, forTest: Boolean = false): String {
        try {
            val json = JSONObject(configJson)
            val outbounds = json.optJSONArray("outbounds") ?: JSONArray()
            val proxies = mutableListOf<Map<String, Any?>>()
            val proxyNames = mutableListOf<String>()

            for (i in 0 until outbounds.length()) {
                val ob = outbounds.optJSONObject(i) ?: continue
                val tag = ob.optString("tag").ifBlank { "Node-${i + 1}" }
                var uniqueName = tag
                var suffix = 2
                while (proxyNames.contains(uniqueName)) {
                    uniqueName = "$tag ($suffix)"
                    suffix++
                }
                val m = convertSingBoxOutboundToMihomo(uniqueName, ob)
                if (m != null) {
                    proxies.add(m)
                    proxyNames.add(uniqueName)
                }
            }

            if (proxies.isNotEmpty()) {
                return buildFullMihomoYaml(proxies, proxyNames, forTest = forTest)
            }
        } catch (_: Exception) {
        }
        return patchRawConfig(configJson, forTest = forTest)
    }

    fun convertSingBoxOutboundToMihomo(name: String, json: JSONObject): Map<String, Any?>? {
        val type = json.optString("type")
        if (type.isBlank() || type in listOf("dns", "block", "direct", "selector", "urltest")) return null
        val server = json.optString("server").takeIf { it.isNotBlank() }
            ?: json.optJSONArray("peers")?.optJSONObject(0)?.optString("server")
            ?: return null
        val port = json.optInt("server_port", 0).takeIf { it > 0 }
            ?: json.optJSONArray("peers")?.optJSONObject(0)?.optInt("server_port", 0)?.takeIf { it > 0 }
            ?: json.optJSONArray("peers")?.optJSONObject(0)?.optInt("port", 0)?.takeIf { it > 0 }
            ?: 443

        val m = linkedMapOf<String, Any?>()
        m["name"] = name

        when (type) {
            "shadowsocks" -> {
                m["type"] = "ss"
                m["server"] = server
                m["port"] = port
                m["cipher"] = json.optString("method", "aes-256-gcm")
                m["password"] = json.optString("password", "")
                m["udp"] = true
                val pluginName = json.optString("plugin")
                val pluginOpts = json.optString("plugin_opts")
                if (pluginName.isNotBlank()) {
                    m["plugin"] = if (pluginOpts.isNotBlank()) "$pluginName;$pluginOpts" else pluginName
                }
            }
            "vmess", "vless" -> {
                val isVless = (type == "vless")
                m["type"] = if (isVless) "vless" else "vmess"
                m["server"] = server
                m["port"] = port
                m["uuid"] = json.optString("uuid", "")
                if (isVless) {
                    m["cipher"] = "none"
                } else {
                    m["alterId"] = json.optInt("alter_id", 0)
                    m["cipher"] = json.optString("security", "auto")
                }
                m["udp"] = true

                val transport = json.optJSONObject("transport")
                val transType = transport?.optString("type")?.lowercase().orEmpty()
                when (transType) {
                    "ws" -> {
                        m["network"] = "ws"
                        val wsOpts = linkedMapOf<String, Any?>()
                        val p = transport?.optString("path").orEmpty()
                        if (p.isNotBlank()) wsOpts["path"] = p
                        val host = transport?.optJSONObject("headers")?.let {
                            it.optString("Host").ifBlank { it.optString("host") }
                        }.orEmpty()
                        if (host.isNotBlank()) wsOpts["headers"] = mapOf("Host" to host)
                        m["ws-opts"] = wsOpts
                    }
                    "grpc" -> {
                        m["network"] = "grpc"
                        val p = transport?.optString("service_name").orEmpty()
                        if (p.isNotBlank()) m["grpc-opts"] = mapOf("grpc-service-name" to p)
                    }
                    "xhttp", "splithttp" -> {
                        m["network"] = "xhttp"
                        val xhttpOpts = linkedMapOf<String, Any?>()
                        val p = transport?.optString("path").orEmpty()
                        if (p.isNotBlank()) xhttpOpts["path"] = p
                        val host = transport?.optJSONObject("headers")?.let {
                            it.optString("Host").ifBlank { it.optString("host") }
                        }.orEmpty()
                        if (host.isNotBlank()) xhttpOpts["headers"] = mapOf("Host" to host)
                        xhttpOpts["mode"] = normalizeXhttpMode(transport?.optString("mode"))
                        m["xhttp-opts"] = xhttpOpts
                    }
                    "h2", "http" -> {
                        m["network"] = "h2"
                        val h2Opts = linkedMapOf<String, Any?>()
                        val host = transport?.optString("host").orEmpty()
                        if (host.isNotBlank()) h2Opts["host"] = listOf(host)
                        val p = transport?.optString("path").orEmpty()
                        if (p.isNotBlank()) h2Opts["path"] = p
                        m["h2-opts"] = h2Opts
                    }
                }

                val tls = json.optJSONObject("tls")
                if (tls != null && tls.optBoolean("enabled", true)) {
                    m["tls"] = true
                    val sni = tls.optString("server_name")
                    if (sni.isNotBlank()) m["servername"] = sni
                    m["skip-cert-verify"] = tls.optBoolean("insecure", false)

                    val utls = tls.optJSONObject("utls")
                    val fp = utls?.optString("fingerprint")?.takeIf { it.isNotBlank() } ?: "chrome"
                    m["client-fingerprint"] = fp

                    val reality = tls.optJSONObject("reality")
                    if (reality != null && reality.optBoolean("enabled", true)) {
                        val realityOpts = linkedMapOf<String, Any?>()
                        realityOpts["public-key"] = reality.optString("public_key")
                        val shortId = reality.optString("short_id")
                        if (shortId.isNotBlank()) realityOpts["short-id"] = shortId
                        m["reality-opts"] = realityOpts
                    } else if (isVless) {
                        val flow = json.optString("flow")
                        if (flow.isNotBlank() && flow.contains("vision")) {
                            m["flow"] = flow
                        }
                    }
                }
            }
            "hysteria2", "hysteria" -> {
                val isHy1 = (type == "hysteria")
                m["type"] = if (isHy1) "hysteria" else "hysteria2"
                m["server"] = server
                m["port"] = port
                val pw = json.optString("password").ifBlank { json.optString("auth_str") }
                if (pw.isNotBlank()) {
                    if (isHy1) m["auth_str"] = pw else m["password"] = pw
                }
                val tls = json.optJSONObject("tls")
                val sni = tls?.optString("server_name")
                if (!sni.isNullOrBlank()) m["sni"] = sni
                m["skip-cert-verify"] = tls?.optBoolean("insecure", false) == true
                val ports = json.optJSONArray("server_ports")?.let { arr ->
                    (0 until arr.length()).map { arr.optString(it).replace(":", "-") }.joinToString(",")
                }
                if (!ports.isNullOrBlank()) m["ports"] = ports
                val obfs = json.optJSONObject("obfs")
                if (obfs != null) {
                    val obfsPw = obfs.optString("password")
                    if (obfsPw.isNotBlank()) {
                        m["obfs"] = "salamander"
                        m["obfs-password"] = obfsPw
                    }
                }
            }
            "trojan" -> {
                m["type"] = "trojan"
                m["server"] = server
                m["port"] = port
                m["password"] = json.optString("password", "")
                val tls = json.optJSONObject("tls")
                val sni = tls?.optString("server_name")
                if (!sni.isNullOrBlank()) m["sni"] = sni
                m["skip-cert-verify"] = tls?.optBoolean("insecure", false) == true
                m["udp"] = true
            }
            "tuic" -> {
                m["type"] = "tuic"
                m["server"] = server
                m["port"] = port
                m["uuid"] = json.optString("uuid", "")
                m["password"] = json.optString("password", "")
                val tls = json.optJSONObject("tls")
                val sni = tls?.optString("server_name")
                if (!sni.isNullOrBlank()) m["sni"] = sni
                m["congestion-controller"] = json.optString("congestion_control", "bbr")
                m["udp"] = true
            }
            "wireguard" -> {
                m["type"] = "wireguard"
                m["server"] = server
                m["port"] = port
                val locArr = json.optJSONArray("local_address")
                if (locArr != null && locArr.length() > 0) {
                    m["ip"] = locArr.optString(0)
                }
                m["public-key"] = json.optString("peer_public_key")
                m["private-key"] = json.optString("private_key")
                m["udp"] = true
            }
            "socks" -> {
                m["type"] = "socks5"
                m["server"] = server
                m["port"] = port
                m["username"] = json.optString("username", "")
                m["password"] = json.optString("password", "")
            }
            "http" -> {
                m["type"] = "http"
                m["server"] = server
                m["port"] = port
                m["username"] = json.optString("username", "")
                m["password"] = json.optString("password", "")
            }
            else -> return null
        }
        return m
    }

    fun buildRootMap(proxies: List<Map<String, Any?>>, proxyNames: List<String>, forTest: Boolean = false): LinkedHashMap<String, Any?> {
        val root = linkedMapOf<String, Any?>()

        // 基础运行模式
        root["mode"] = "rule"
        root["log-level"] = when (DataStore.logLevel) {
            0 -> "silent"
            1 -> "warning"
            2 -> "info"
            3 -> "debug"
            else -> "info"
        }
        root["ipv6"] = DataStore.ipv6Mode > 0
        if (!forTest) {
            root["external-controller"] = "127.0.0.1:9090"
            root["secret"] = ""
            // 本地入站端口与局域网共享
            if (!DataStore.disableMixedInbound) {
                root["mixed-port"] = DataStore.mixedPort
            }
            root["allow-lan"] = DataStore.allowAccess
            root["bind-address"] = "*"
        }

        // TUN 配置
        val tunMap = linkedMapOf<String, Any?>()
        tunMap["enable"] = !forTest
        tunMap["stack"] = when (DataStore.tunImplementation) {
            0 -> "gvisor"
            1 -> "system"
            2 -> "mixed"
            else -> "gvisor"
        }
        tunMap["device"] = "tun0"
        tunMap["auto-route"] = false // 由 Android VpnService 接管系统路由表
        tunMap["auto-detect-interface"] = false // 由 Android VpnService.protect() 保护出站套接字
        tunMap["mtu"] = DataStore.mtu
        tunMap["dns-hijack"] = listOf("172.19.0.2:53", "0.0.0.0:53")
        root["tun"] = tunMap

        // DNS 配置
        val dnsMap = linkedMapOf<String, Any?>()
        dnsMap["enable"] = true
        if (!forTest) {
            dnsMap["listen"] = "0.0.0.0:1053"
        }
        dnsMap["enhanced-mode"] = if (DataStore.enableFakeDns) "fake-ip" else "redir-host"
        dnsMap["fake-ip-range"] = "198.18.0.1/16"
        dnsMap["default-nameserver"] = listOf("223.5.5.5", "119.29.29.29", "1.1.1.1")
        val nameservers = mutableListOf<String>()
        if (DataStore.directDns.isNotBlank()) nameservers.add(DataStore.directDns.trim())
        if (DataStore.remoteDns.isNotBlank()) nameservers.add(DataStore.remoteDns.trim())
        nameservers.addAll(listOf("https://doh.pub/dns-query", "223.5.5.5", "119.29.29.29", "1.1.1.1", "8.8.8.8"))
        dnsMap["nameserver"] = nameservers.distinct()
        root["dns"] = dnsMap

        // 流量嗅探 (Sniffer)
        val sniffer = linkedMapOf<String, Any?>()
        sniffer["enable"] = !forTest
        sniffer["parse-pure-ip"] = true
        sniffer["sniff"] = mapOf(
            "TLS" to mapOf("ports" to listOf(443, 8443)),
            "HTTP" to mapOf("ports" to listOf(80, "8080-8880")),
            "QUIC" to mapOf("ports" to listOf(443))
        )
        sniffer["skip-domain"] = listOf("Mijia Cloud", "dlg.io.mi.com", "+.apple.com")
        root["sniffer"] = sniffer

        // NTP 内置时间校准
        root["ntp"] = mapOf(
            "enable" to !forTest,
            "server" to "time.apple.com",
            "port" to 123,
            "interval" to 30
        )

        // 代理节点列表
        root["proxies"] = proxies

        // 策略组
        val proxyGroups = mutableListOf<Map<String, Any?>>()
        val selectGroup = linkedMapOf<String, Any?>()
        selectGroup["name"] = "PROXY"
        selectGroup["type"] = "select"
        val selectTargets = mutableListOf<String>()
        selectTargets.addAll(proxyNames)
        if (proxyNames.size > 1) {
            selectTargets.add("AUTO")
            selectTargets.add("FALLBACK")
        }
        selectTargets.add("DIRECT")
        selectGroup["proxies"] = selectTargets
        proxyGroups.add(selectGroup)

        if (proxyNames.size > 1) {
            val autoGroup = linkedMapOf<String, Any?>()
            autoGroup["name"] = "AUTO"
            autoGroup["type"] = "url-test"
            autoGroup["url"] = "http://www.gstatic.com/generate_204"
            autoGroup["interval"] = 300
            autoGroup["proxies"] = proxyNames
            proxyGroups.add(autoGroup)

            val fallbackGroup = linkedMapOf<String, Any?>()
            fallbackGroup["name"] = "FALLBACK"
            fallbackGroup["type"] = "fallback"
            fallbackGroup["url"] = "http://www.gstatic.com/generate_204"
            fallbackGroup["interval"] = 300
            fallbackGroup["proxies"] = proxyNames
            proxyGroups.add(fallbackGroup)
        }
        root["proxy-groups"] = proxyGroups
        root["geox-url"] = mapOf(
            "geosite" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
            "geoip" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            "mmdb" to "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
        )
        root["geo-auto-update"] = false

        if (forTest) {
            root["rules"] = listOf("MATCH,${proxyNames.firstOrNull() ?: "PROXY"}")
            return root
        }

        // 分流规则
        val hasGeosite = hasGeoSite()
        val hasGeoip = hasGeoIP()
        val rules = mutableListOf<String>()
        if (DataStore.bypassLan) {
            rules.add("GEOIP,lan,DIRECT,no-resolve")
        }
        // 载入用户自定义规则库
        try {
            val dbRules = SagerDatabase.rulesDao.enabledRules()
            for (r in dbRules) {
                val target = when (r.outbound) {
                    -1L -> "DIRECT"
                    -2L -> "REJECT"
                    else -> "PROXY"
                }
                if (r.domains.isNotBlank()) {
                    for (d in r.domains.split("\n")) {
                        val td = d.trim()
                        if (td.isBlank()) continue
                        if (td.startsWith("geosite:")) {
                            val site = td.removePrefix("geosite:")
                            if (hasGeosite) {
                                rules.add("GEOSITE,$site,$target")
                            } else {
                                when (site) {
                                    "category-ads-all" -> {
                                        rules.add("DOMAIN-KEYWORD,adservice,$target")
                                        rules.add("DOMAIN-KEYWORD,telemetry,$target")
                                    }
                                    "cn" -> {
                                        rules.add("DOMAIN-SUFFIX,cn,$target")
                                    }
                                    else -> {
                                        Logs.w("geosite.dat not found locally, skipping GEOSITE,$site")
                                    }
                                }
                            }
                        } else if (td.startsWith("full:") || td.startsWith("domain:")) {
                            rules.add("DOMAIN," + td.substringAfter(":") + ",$target")
                        } else if (td.startsWith("keyword:")) {
                            rules.add("DOMAIN-KEYWORD," + td.substringAfter(":") + ",$target")
                        } else {
                            rules.add("DOMAIN-SUFFIX,$td,$target")
                        }
                    }
                }
                if (r.ip.isNotBlank()) {
                    for (ip in r.ip.split("\n")) {
                        val tip = ip.trim()
                        if (tip.isBlank()) continue
                        if (tip.startsWith("geoip:")) {
                            val code = tip.removePrefix("geoip:")
                            if (code.equals("lan", ignoreCase = true) || code.equals("private", ignoreCase = true)) {
                                rules.add("GEOIP,$code,$target,no-resolve")
                            } else if (hasGeoip) {
                                rules.add("GEOIP,$code,$target")
                            } else {
                                Logs.w("geoip.dat not found locally, skipping GEOIP,$code")
                            }
                        } else {
                            rules.add("IP-CIDR,$tip,$target")
                        }
                    }
                }
                if (r.port.isNotBlank()) {
                    for (p in r.port.split(",")) {
                        val tp = p.trim()
                        if (tp.isNotBlank()) rules.add("DST-PORT,$tp,$target")
                    }
                }
                if (r.protocol.equals("quic", ignoreCase = true) && r.outbound == -2L) {
                    rules.add("AND,((NETWORK,udp),(DST-PORT,443)),REJECT")
                }
            }
        } catch (_: Exception) {
        }
        if (DataStore.bypass) {
            if (hasGeosite) {
                rules.add("GEOSITE,cn,DIRECT")
            } else {
                rules.add("DOMAIN-SUFFIX,cn,DIRECT")
            }
            if (hasGeoip) {
                rules.add("GEOIP,CN,DIRECT")
            }
        }
        rules.add("MATCH,PROXY")
        root["rules"] = rules

        return root
    }

    fun buildFullMihomoYaml(proxies: List<Map<String, Any?>>, proxyNames: List<String>, forTest: Boolean = false): String {
        val root = buildRootMap(proxies, proxyNames, forTest = forTest)
        val options = DumperOptions().apply {
            defaultFlowStyle = DumperOptions.FlowStyle.BLOCK
            isPrettyFlow = true
        }
        return Yaml(options).dump(root) ?: ""
    }

    fun buildSingleProxy(name: String, profile: ProxyEntity): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>()
        m["name"] = name

        val vmess = profile.vmessBean
        val hy = profile.hysteriaBean
        val trojan = profile.trojanBean
        val ss = profile.ssBean
        val ssr = profile.ssrBean
        val tuic = profile.tuicBean
        val wg = profile.wgBean
        val snell = profile.snellBean
        val socks = profile.socksBean
        val http = profile.httpBean
        val config = profile.configBean

        when {
            // ConfigBean 兼容
            config != null && config.config.isNotBlank() -> {
                val text = config.config.trim()
                if (text.startsWith("{")) {
                    try {
                        val jsonObj = JSONObject(text)
                        val converted = convertSingBoxOutboundToMihomo(name, jsonObj)
                        if (converted != null) return converted
                    } catch (_: Exception) {}
                } else {
                    try {
                        val loaded = Yaml().load<Any>(text)
                        if (loaded is Map<*, *>) {
                            val yamlMap = LinkedHashMap<String, Any?>()
                            for ((k, v) in loaded) {
                                if (k != null) yamlMap[k.toString()] = v
                            }
                            yamlMap["name"] = name
                            if (yamlMap.containsKey("type") && yamlMap.containsKey("server")) {
                                return yamlMap
                            }
                        }
                    } catch (_: Exception) {}
                }
                m["type"] = "socks5"
                m["server"] = "127.0.0.1"
                m["port"] = 1080
            }

            // VLESS (alterId == -1) 或 VMess
            vmess != null -> {
                if (vmess.alterId == -1) {
                    m["type"] = "vless"
                    m["server"] = vmess.serverAddress ?: ""
                    m["port"] = vmess.serverPort ?: 443
                    m["uuid"] = vmess.uuid ?: ""
                    m["cipher"] = "none"
                    m["udp"] = true

                    val netType = vmess.type?.lowercase().orEmpty()
                    when (netType) {
                        "xhttp", "splithttp" -> {
                            m["network"] = "xhttp"
                            val xhttpOpts = linkedMapOf<String, Any?>()
                            xhttpOpts["mode"] = normalizeXhttpMode(vmess.xhttpMode)
                            if (!vmess.path.isNullOrBlank()) xhttpOpts["path"] = vmess.path
                            if (!vmess.host.isNullOrBlank()) {
                                xhttpOpts["headers"] = mapOf("Host" to vmess.host)
                            }
                            if (!vmess.xhttpExtra.isNullOrBlank()) {
                                xhttpOpts["extra"] = vmess.xhttpExtra
                            }
                            m["xhttp-opts"] = xhttpOpts
                        }
                        "ws" -> {
                            m["network"] = "ws"
                            val wsOpts = linkedMapOf<String, Any?>()
                            if (!vmess.path.isNullOrBlank()) wsOpts["path"] = vmess.path
                            if (!vmess.host.isNullOrBlank()) {
                                wsOpts["headers"] = mapOf("Host" to vmess.host)
                            }
                            m["ws-opts"] = wsOpts
                        }
                        "grpc" -> {
                            m["network"] = "grpc"
                            if (!vmess.path.isNullOrBlank()) {
                                m["grpc-opts"] = mapOf("grpc-service-name" to vmess.path)
                            }
                        }
                        "h2", "http" -> {
                            m["network"] = "h2"
                            val h2Opts = linkedMapOf<String, Any?>()
                            if (!vmess.host.isNullOrBlank()) h2Opts["host"] = listOf(vmess.host)
                            if (!vmess.path.isNullOrBlank()) h2Opts["path"] = vmess.path
                            m["h2-opts"] = h2Opts
                        }
                    }

                    val isReality = (vmess.security == "reality" || !vmess.realityPubKey.isNullOrBlank())
                    if (isReality) {
                        m["tls"] = true
                        if (!vmess.sni.isNullOrBlank()) m["servername"] = vmess.sni
                        val realityOpts = linkedMapOf<String, Any?>()
                        realityOpts["public-key"] = vmess.realityPubKey ?: ""
                        if (!vmess.realityShortId.isNullOrBlank()) {
                            realityOpts["short-id"] = vmess.realityShortId
                        }
                        m["reality-opts"] = realityOpts
                        m["client-fingerprint"] = if (!vmess.utlsFingerprint.isNullOrBlank()) vmess.utlsFingerprint else "chrome"
                    } else if (vmess.security == "tls" || vmess.isTLS()) {
                        m["tls"] = true
                        if (!vmess.sni.isNullOrBlank()) m["servername"] = vmess.sni
                        m["skip-cert-verify"] = vmess.allowInsecure == true
                        if (!vmess.encryption.isNullOrBlank() && vmess.encryption.contains("vision")) {
                            m["flow"] = vmess.encryption
                        }
                        if (!vmess.alpn.isNullOrBlank()) {
                            m["alpn"] = vmess.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                        }
                        m["client-fingerprint"] = if (!vmess.utlsFingerprint.isNullOrBlank()) vmess.utlsFingerprint else "chrome"
                    }
                } else {
                    // VMess
                    m["type"] = "vmess"
                    m["server"] = vmess.serverAddress ?: ""
                    m["port"] = vmess.serverPort ?: 443
                    m["uuid"] = vmess.uuid ?: ""
                    m["alterId"] = vmess.alterId ?: 0
                    m["cipher"] = if (!vmess.encryption.isNullOrBlank()) vmess.encryption else "auto"
                    m["udp"] = true
                    val netType = vmess.type?.lowercase().orEmpty()
                    when (netType) {
                        "ws" -> {
                            m["network"] = "ws"
                            val wsOpts = linkedMapOf<String, Any?>()
                            if (!vmess.path.isNullOrBlank()) wsOpts["path"] = vmess.path
                            if (!vmess.host.isNullOrBlank()) {
                                wsOpts["headers"] = mapOf("Host" to vmess.host)
                            }
                            m["ws-opts"] = wsOpts
                        }
                        "grpc" -> {
                            m["network"] = "grpc"
                            if (!vmess.path.isNullOrBlank()) {
                                m["grpc-opts"] = mapOf("grpc-service-name" to vmess.path)
                            }
                        }
                        "h2", "http" -> {
                            m["network"] = "h2"
                            val h2Opts = linkedMapOf<String, Any?>()
                            if (!vmess.host.isNullOrBlank()) h2Opts["host"] = listOf(vmess.host)
                            if (!vmess.path.isNullOrBlank()) h2Opts["path"] = vmess.path
                            m["h2-opts"] = h2Opts
                        }
                        else -> if (netType.isNotBlank()) m["network"] = netType
                    }
                    if (vmess.security == "tls" || vmess.isTLS()) {
                        m["tls"] = true
                        if (!vmess.sni.isNullOrBlank()) m["servername"] = vmess.sni
                        m["skip-cert-verify"] = vmess.allowInsecure == true
                        if (!vmess.alpn.isNullOrBlank()) {
                            m["alpn"] = vmess.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                        }
                        m["client-fingerprint"] = if (!vmess.utlsFingerprint.isNullOrBlank()) vmess.utlsFingerprint else "chrome"
                    }
                }
            }

            // Hysteria 1 / 2
            hy != null -> {
                val isHy1 = (hy.protocolVersion == 1)
                m["type"] = if (isHy1) "hysteria" else "hysteria2"
                m["server"] = hy.serverAddress ?: ""
                val defaultPort = hy.serverPorts?.split(',', '-')?.firstOrNull()?.trim()?.toIntOrNull() ?: 443
                m["port"] = if ((hy.serverPort ?: 0) > 0) hy.serverPort else defaultPort
                if (!hy.authPayload.isNullOrBlank()) {
                    if (isHy1) {
                        m["auth_str"] = hy.authPayload
                    } else {
                        m["password"] = hy.authPayload
                    }
                }
                if (!hy.sni.isNullOrBlank()) m["sni"] = hy.sni
                m["skip-cert-verify"] = hy.allowInsecure == true
                if ((hy.uploadMbps ?: 0) > 0) m["up"] = "${hy.uploadMbps} Mbps"
                if ((hy.downloadMbps ?: 0) > 0) m["down"] = "${hy.downloadMbps} Mbps"
                if (!hy.serverPorts.isNullOrBlank()) m["ports"] = hy.serverPorts
                if (!hy.obfuscation.isNullOrBlank()) {
                    m["obfs"] = "salamander"
                    m["obfs-password"] = hy.obfuscation
                }
                if (isHy1 && !hy.alpn.isNullOrBlank()) {
                    m["alpn"] = hy.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                }
            }

            // Trojan
            trojan != null -> {
                m["type"] = "trojan"
                m["server"] = trojan.serverAddress ?: ""
                m["port"] = trojan.serverPort ?: 443
                m["password"] = trojan.password ?: ""
                if (!trojan.sni.isNullOrBlank()) m["sni"] = trojan.sni
                m["skip-cert-verify"] = trojan.allowInsecure == true
                if (!trojan.alpn.isNullOrBlank()) {
                    m["alpn"] = trojan.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                }
                val netType = trojan.type?.lowercase().orEmpty()
                if (netType == "ws") {
                    m["network"] = "ws"
                    val wsOpts = linkedMapOf<String, Any?>()
                    if (!trojan.path.isNullOrBlank()) wsOpts["path"] = trojan.path
                    if (!trojan.host.isNullOrBlank()) wsOpts["headers"] = mapOf("Host" to trojan.host)
                    m["ws-opts"] = wsOpts
                } else if (netType == "grpc") {
                    m["network"] = "grpc"
                    if (!trojan.path.isNullOrBlank()) {
                        m["grpc-opts"] = mapOf("grpc-service-name" to trojan.path)
                    }
                }
                m["udp"] = true
            }

            // Shadowsocks
            ss != null -> {
                m["type"] = "ss"
                m["server"] = ss.serverAddress ?: ""
                m["port"] = ss.serverPort ?: 8388
                m["cipher"] = if (!ss.method.isNullOrBlank()) ss.method else "aes-256-gcm"
                m["password"] = ss.password ?: ""
                m["udp"] = true
                if (!ss.plugin.isNullOrBlank()) {
                    m["plugin"] = ss.plugin
                }
            }

            // ShadowsocksR
            ssr != null -> {
                m["type"] = "ssr"
                m["server"] = ssr.serverAddress ?: ""
                m["port"] = ssr.serverPort ?: 8388
                m["cipher"] = if (!ssr.method.isNullOrBlank()) ssr.method else "aes-256-cfb"
                m["password"] = ssr.password ?: ""
                m["protocol"] = if (!ssr.protocol.isNullOrBlank()) ssr.protocol else "origin"
                if (!ssr.protocolParam.isNullOrBlank()) m["protocol-param"] = ssr.protocolParam
                m["obfs"] = if (!ssr.obfs.isNullOrBlank()) ssr.obfs else "plain"
                if (!ssr.obfsParam.isNullOrBlank()) m["obfs-param"] = ssr.obfsParam
                m["udp"] = true
            }

            // TUIC
            tuic != null -> {
                m["type"] = "tuic"
                m["server"] = tuic.serverAddress ?: ""
                m["port"] = tuic.serverPort ?: 8443
                m["uuid"] = tuic.uuid ?: ""
                m["password"] = tuic.token ?: ""
                if (!tuic.sni.isNullOrBlank()) m["sni"] = tuic.sni
                m["congestion-controller"] = if (!tuic.congestionController.isNullOrBlank()) tuic.congestionController else "bbr"
                if (!tuic.alpn.isNullOrBlank()) {
                    m["alpn"] = tuic.alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                }
                m["udp"] = true
                m["skip-cert-verify"] = tuic.allowInsecure == true
            }

            // WireGuard
            wg != null -> {
                m["type"] = "wireguard"
                m["server"] = wg.serverAddress ?: ""
                m["port"] = wg.serverPort ?: 51820
                m["ip"] = wg.localAddress ?: ""
                m["public-key"] = wg.peerPublicKey ?: ""
                m["private-key"] = wg.privateKey ?: ""
                m["udp"] = true
                if (!wg.reserved.isNullOrBlank()) {
                    try {
                        m["reserved"] = wg.reserved.split(",").map { it.trim().toInt() }
                    } catch (_: Exception) {
                    }
                }
                if ((wg.mtu ?: 0) > 0) m["mtu"] = wg.mtu
            }

            // Snell
            snell != null -> {
                m["type"] = "snell"
                m["server"] = snell.serverAddress ?: ""
                m["port"] = snell.serverPort ?: 443
                m["psk"] = snell.psk ?: ""
                m["version"] = snell.version
                if (!snell.obfsMode.isNullOrBlank() && snell.obfsMode != "off") {
                    val obfsOpts = linkedMapOf<String, Any?>()
                    obfsOpts["mode"] = snell.obfsMode
                    if (!snell.obfsHost.isNullOrBlank()) obfsOpts["host"] = snell.obfsHost
                    m["obfs-opts"] = obfsOpts
                }
                m["udp"] = true
            }

            // SOCKS5
            socks != null -> {
                m["type"] = "socks5"
                m["server"] = socks.serverAddress ?: "127.0.0.1"
                m["port"] = socks.serverPort ?: 1080
                if (!socks.username.isNullOrBlank()) m["username"] = socks.username
                if (!socks.password.isNullOrBlank()) m["password"] = socks.password
            }

            // HTTP
            http != null -> {
                m["type"] = "http"
                m["server"] = http.serverAddress ?: "127.0.0.1"
                m["port"] = http.serverPort ?: 8080
                if (!http.username.isNullOrBlank()) m["username"] = http.username
                if (!http.password.isNullOrBlank()) m["password"] = http.password
                if (http.security == "tls") {
                    m["tls"] = true
                    if (!http.sni.isNullOrBlank()) m["sni"] = http.sni
                }
            }

            // 回退到 Socks5
            else -> {
                m["type"] = "socks5"
                m["server"] = "127.0.0.1"
                m["port"] = 1080
            }
        }

        return m
    }
}
