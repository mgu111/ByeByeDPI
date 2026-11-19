package io.github.romanvht.byedpi.services

import io.github.romanvht.byedpi.BuildConfig

internal object EngineProtocol {
    const val HELLO = 1
    const val START = 2
    const val STOP = 3
    const val HELLO_ACK = 4
    const val STARTED = 5
    const val FAILED = 6
    const val STOPPING = 7
    const val CONFIGURED = 8

    const val CONTROL_ACTION = "${BuildConfig.APPLICATION_ID}.ENGINE"
    const val BOUND_CONTROL_ACTION = "${BuildConfig.APPLICATION_ID}.BOUND_ENGINE"
    const val STATE_IDLE = 0
    const val STATE_STARTING = 1
    const val STATE_RUNNING = 2
    const val STATE_STOPPING = 3

    const val ARGS = "args"
    const val HOST = "host"
    const val PORT = "port"
    const val DNS = "dns"
    const val IPV6 = "ipv6"
    const val APP_LIST_TYPE = "app_list_type"
    const val APPS = "apps"
    const val DNS_MODE = "dns_mode"
    const val DNS_SERVER = "dns_server"
    const val DNS_FALLBACK = "dns_fallback"
    const val DNS_HOSTS = "dns_hosts"
    const val DNS_IPV4_ONLY = "dns_ipv4_only"
    const val DNS_VIA_PROXY = "dns_via_proxy"
    const val PID = "pid"
    const val STATE = "state"
    const val ERROR = "error"
}
