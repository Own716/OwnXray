package io.nekohasekai.sagernet.bg.mihomo

import io.nekohasekai.sagernet.ktx.Logs
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * OwnXray 核心 RESTful & WebSocket API 集中通信客户端
 * 遵循「UI 层 <-> 核心实例 <-> 本地控制 API」解耦架构，
 * 负责流量监听、节点延迟测试、出站模式切换与热重载。
 */
object MihomoApiClient {

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    private val wsClient = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    private fun getBaseUrl(): String {
        return "http://127.0.0.1:9090"
    }

    private fun getWsUrl(path: String): String {
        return "ws://127.0.0.1:9090$path"
    }

    private fun buildRequest(url: String): Request.Builder {
        return Request.Builder().url(url)
    }

    // 1. 实时上下行流量推送 (WebSocket /traffic)
    data class Traffic(val up: Long, val down: Long)

    private val _trafficFlow = MutableSharedFlow<Traffic>(replay = 1)
    val trafficFlow: SharedFlow<Traffic> = _trafficFlow.asSharedFlow()
    private var trafficWs: WebSocket? = null

    @Synchronized
    fun startTrafficSubscription(scope: CoroutineScope) {
        if (trafficWs != null) return
        val req = buildRequest(getWsUrl("/traffic")).build()
        trafficWs = wsClient.newWebSocket(req, object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                try {
                    val obj = JSONObject(text)
                    val up = obj.optLong("up", 0L)
                    val down = obj.optLong("down", 0L)
                    scope.launch { _trafficFlow.emit(Traffic(up, down)) }
                } catch (_: Exception) {
                }
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                trafficWs = null
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                trafficWs = null
            }
        })
    }

    @Synchronized
    fun stopTrafficSubscription() {
        trafficWs?.close(1000, "close")
        trafficWs = null
    }

    // 2. 出站模式切换 (PATCH /configs)
    suspend fun switchMode(mode: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().put("mode", mode).toString().toRequestBody(jsonMediaType)
            val req = buildRequest("${getBaseUrl()}/configs").patch(body).build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            Logs.w(e)
            false
        }
    }

    // 3. 内核配置热重载 (PUT /configs?force=true)
    suspend fun reloadConfig(path: String = "", force: Boolean = true): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().apply {
                if (path.isNotBlank()) put("path", path)
            }.toString().toRequestBody(jsonMediaType)
            val req = buildRequest("${getBaseUrl()}/configs?force=$force").put(body).build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            Logs.w(e)
            false
        }
    }

    // 4. 节点与策略组查询 (GET /proxies)
    data class ProxyNode(
        val name: String,
        val type: String,
        val now: String?,
        val all: List<String>,
        val delay: Int
    )

    suspend fun getProxies(): Map<String, ProxyNode> = withContext(Dispatchers.IO) {
        val result = mutableMapOf<String, ProxyNode>()
        try {
            val req = buildRequest("${getBaseUrl()}/proxies").get().build()
            httpClient.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val json = JSONObject(resp.body?.string().orEmpty())
                    val proxies = json.optJSONObject("proxies") ?: return@use
                    val keys = proxies.keys()
                    while (keys.hasNext()) {
                        val key = keys.next()
                        val obj = proxies.optJSONObject(key) ?: continue
                        val name = obj.optString("name", key)
                        val type = obj.optString("type", "")
                        val now = obj.optString("now", "").takeIf { it.isNotBlank() }
                        val allArr = obj.optJSONArray("all")
                        val allList = mutableListOf<String>()
                        if (allArr != null) {
                            for (i in 0 until allArr.length()) {
                                allList.add(allArr.getString(i))
                            }
                        }
                        val historyArr = obj.optJSONArray("history")
                        val lastDelay = if (historyArr != null && historyArr.length() > 0) {
                            historyArr.getJSONObject(historyArr.length() - 1).optInt("delay", 0)
                        } else 0
                        result[name] = ProxyNode(name, type, now, allList, lastDelay)
                    }
                }
            }
        } catch (e: Exception) {
            Logs.w(e)
        }
        result
    }

    // 5. 策略组节点切换 (PUT /proxies/{group})
    suspend fun selectProxy(group: String, proxyName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val body = JSONObject().put("name", proxyName).toString().toRequestBody(jsonMediaType)
            val req = buildRequest("${getBaseUrl()}/proxies/$group").put(body).build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            Logs.w(e)
            false
        }
    }

    // 6. 节点延迟测试 (GET /proxies/{node}/delay)
    suspend fun testDelay(
        nodeName: String,
        url: String = "http://cp.cloudflare.com/generate_204",
        timeoutMs: Int = 5000
    ): Int = withContext(Dispatchers.IO) {
        try {
            val req = buildRequest("${getBaseUrl()}/proxies/$nodeName/delay?url=$url&timeout=$timeoutMs").get().build()
            httpClient.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val json = JSONObject(resp.body?.string().orEmpty())
                    return@withContext json.optInt("delay", -1)
                }
            }
        } catch (e: Exception) {
            Logs.w(e)
        }
        -1
    }

    // 7. 连接管理 (DELETE /connections)
    suspend fun closeConnection(id: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val req = buildRequest("${getBaseUrl()}/connections/$id").delete().build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            false
        }
    }

    suspend fun closeAllConnections(): Boolean = withContext(Dispatchers.IO) {
        try {
            val req = buildRequest("${getBaseUrl()}/connections").delete().build()
            httpClient.newCall(req).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            false
        }
    }
}
