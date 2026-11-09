package org.example

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ServerMonitorTest {
    @Test
    fun `browser probe derives from the stored public IP without an allowlist`() {
        assertEquals("https://83-141-80-158.sslip.io/_inoagent/health", browserProbeUrl("83.141.80.158"))
        for (host in listOf("127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1", "83.141.80.999", "008.8.8.8")) {
            assertNull(browserProbeUrl(host), host)
        }
    }
}
