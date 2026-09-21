firewall {
    all-ping enable
    broadcast-ping disable
    ipv6-name WANv6_IN {
        default-action drop
        description "WAN inbound traffic forwarded to LAN"
        rule 10 {
            action accept
            description "Allow established/related"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 30 {
            action accept
            description "Allow local"
            log disable
            protocol all
            source {
                address 2001:db8:99::/48
            }
        }
        rule 40 {
            action accept
            description "Allow icmp"
            log disable
            protocol ipv6-icmp
        }
        rule 100 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 53 udp"
            destination {
                address 2001:db8:99:5930:9a03:9bff:fe56:593
                port 53
            }
            log disable
            protocol udp
        }
        rule 110 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 80 tcp"
            destination {
                address 2001:db8:99:5930:9a03:9bff:fe56:593
                port 80
            }
            log disable
            protocol tcp
        }
        rule 120 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 443"
            destination {
                address 2001:db8:99:5930:9a03:9bff:fe56:593
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 444 tcp"
            destination {
                address 2001:db8:99:5930:9a03:9bff:fe56:593
                port 444
            }
            log disable
            protocol tcp
        }
        rule 140 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 1080 tcp"
            destination {
                address 2001:db8:99:5930:9a03:9bff:fe56:593
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp fireside eno1np0 alt 53 udp"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 53
            }
            log disable
            protocol udp
        }
        rule 160 {
            action accept
            description "warp fireside eno1np0 alt 443 udp"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 443
            }
            log disable
            protocol udp
        }
        rule 170 {
            action accept
            description "warp fireside eno1np0 alt 4053 udp"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 4053
            }
            log disable
            protocol udp
        }
        rule 180 {
            action accept
            description "warp fireside eno1np0 proxy g1 socks"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7011
            }
            log disable
            protocol tcp_udp
        }
        rule 190 {
            action accept
            description "warp fireside eno1np0 proxy g1 http"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7012
            }
            log disable
            protocol tcp_udp
        }
        rule 200 {
            action accept
            description "warp fireside eno1np0 proxy g1 https"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7013
            }
            log disable
            protocol tcp_udp
        }
        rule 210 {
            action accept
            description "warp fireside eno1np0 proxy g1 api"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7014
            }
            log disable
            protocol tcp_udp
        }
        rule 220 {
            action accept
            description "warp fireside eno1np0 proxy g1 wg"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7015
            }
            log disable
            protocol tcp_udp
        }
        rule 230 {
            action accept
            description "warp fireside eno1np0 proxy g2 socks"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7017
            }
            log disable
            protocol tcp_udp
        }
        rule 240 {
            action accept
            description "warp fireside eno1np0 proxy g2 http"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7018
            }
            log disable
            protocol tcp_udp
        }
        rule 250 {
            action accept
            description "warp fireside eno1np0 proxy g2 https"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7019
            }
            log disable
            protocol tcp_udp
        }
        rule 260 {
            action accept
            description "warp fireside eno1np0 proxy g2 api"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7020
            }
            log disable
            protocol tcp_udp
        }
        rule 270 {
            action accept
            description "warp fireside eno1np0 proxy g2 wg"
            destination {
                address 2001:db8:99:5960:3a05:25ff:fe32:e5ab
                port 7021
            }
            log disable
            protocol tcp_udp
        }
        rule 9000 {
            action drop
            description "Log a sample of the dropped traffic"
            limit {
                burst 10
                rate 5/second
            }
            log enable
            protocol all
        }
    }
    ipv6-name WANv6_LOCAL {
        default-action drop
        description "WAN inbound traffic to the router"
        rule 10 {
            action accept
            description "Allow established/related"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 30 {
            action accept
            description "Allow icmp echo up to the limit"
            icmpv6 {
                type echo-request
            }
            limit {
                burst 20
                rate 10/second
            }
            log disable
            protocol ipv6-icmp
        }
        rule 31 {
            action drop
            description "Drop icmp echo over the limit"
            icmpv6 {
                type echo-request
            }
            log disable
            protocol ipv6-icmp
        }
        rule 32 {
            action accept
            description "Allow icmp"
            log disable
            protocol ipv6-icmp
        }
        rule 9000 {
            action drop
            description "Log a sample of the dropped traffic"
            limit {
                burst 10
                rate 5/second
            }
            log enable
            protocol all
        }
    }
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    name WAN_IN {
        default-action drop
        description "WAN to internal"
        rule 10 {
            action accept
            description "Allow established/related"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 30 {
            action accept
            description "Allow local"
            log disable
            protocol all
            source {
                address 203.0.113.64/27
            }
        }
        rule 40 {
            action accept
            description "Allow icmp"
            log disable
            protocol icmp
        }
        rule 100 {
            action accept
            description "warp edge-5 enp33s0f1np1 forward 8022 to 22 tcp"
            destination {
                address 203.0.113.91
                port 22
            }
            log disable
            protocol tcp
        }
        rule 110 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 53 udp"
            destination {
                address 203.0.113.91
                port 53
            }
            log disable
            protocol udp
        }
        rule 120 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 80 tcp"
            destination {
                address 203.0.113.91
                port 80
            }
            log disable
            protocol tcp
        }
        rule 130 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 443"
            destination {
                address 203.0.113.91
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 140 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 444 tcp"
            destination {
                address 203.0.113.91
                port 444
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp edge-5 enp33s0f1np1 lb 1080 tcp"
            destination {
                address 203.0.113.91
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 160 {
            action accept
            description "warp fireside eno1np0 alt 53 udp"
            destination {
                address 203.0.113.92
                port 53
            }
            log disable
            protocol udp
        }
        rule 170 {
            action accept
            description "warp fireside eno1np0 alt 443 udp"
            destination {
                address 203.0.113.92
                port 443
            }
            log disable
            protocol udp
        }
        rule 180 {
            action accept
            description "warp fireside eno1np0 alt 4053 udp"
            destination {
                address 203.0.113.92
                port 4053
            }
            log disable
            protocol udp
        }
        rule 190 {
            action accept
            description "warp fireside eno1np0 proxy g1 socks"
            destination {
                address 203.0.113.92
                port 7011
            }
            log disable
            protocol tcp_udp
        }
        rule 200 {
            action accept
            description "warp fireside eno1np0 proxy g1 http"
            destination {
                address 203.0.113.92
                port 7012
            }
            log disable
            protocol tcp_udp
        }
        rule 210 {
            action accept
            description "warp fireside eno1np0 proxy g1 https"
            destination {
                address 203.0.113.92
                port 7013
            }
            log disable
            protocol tcp_udp
        }
        rule 220 {
            action accept
            description "warp fireside eno1np0 proxy g1 api"
            destination {
                address 203.0.113.92
                port 7014
            }
            log disable
            protocol tcp_udp
        }
        rule 230 {
            action accept
            description "warp fireside eno1np0 proxy g1 wg"
            destination {
                address 203.0.113.92
                port 7015
            }
            log disable
            protocol tcp_udp
        }
        rule 240 {
            action accept
            description "warp fireside eno1np0 proxy g2 socks"
            destination {
                address 203.0.113.92
                port 7017
            }
            log disable
            protocol tcp_udp
        }
        rule 250 {
            action accept
            description "warp fireside eno1np0 proxy g2 http"
            destination {
                address 203.0.113.92
                port 7018
            }
            log disable
            protocol tcp_udp
        }
        rule 260 {
            action accept
            description "warp fireside eno1np0 proxy g2 https"
            destination {
                address 203.0.113.92
                port 7019
            }
            log disable
            protocol tcp_udp
        }
        rule 270 {
            action accept
            description "warp fireside eno1np0 proxy g2 api"
            destination {
                address 203.0.113.92
                port 7020
            }
            log disable
            protocol tcp_udp
        }
        rule 280 {
            action accept
            description "warp fireside eno1np0 proxy g2 wg"
            destination {
                address 203.0.113.92
                port 7021
            }
            log disable
            protocol tcp_udp
        }
        rule 9000 {
            action drop
            description "Log a sample of the dropped traffic"
            limit {
                burst 10
                rate 5/second
            }
            log enable
            protocol all
        }
    }
    name WAN_LOCAL {
        default-action drop
        description "WAN to router"
        rule 10 {
            action accept
            description "Allow established/related"
            state {
                established enable
                related enable
            }
        }
        rule 20 {
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 30 {
            action accept
            description "Allow icmp echo up to the limit"
            icmp {
                type 8
            }
            limit {
                burst 20
                rate 10/second
            }
            log disable
            protocol icmp
        }
        rule 31 {
            action drop
            description "Drop icmp echo over the limit"
            icmp {
                type 8
            }
            log disable
            protocol icmp
        }
        rule 32 {
            action accept
            description "Allow icmp"
            log disable
            protocol icmp
        }
        rule 9000 {
            action drop
            description "Log a sample of the dropped traffic"
            limit {
                burst 10
                rate 5/second
            }
            log enable
            protocol all
        }
    }
    receive-redirects disable
    send-redirects disable
    source-validation disable
    syn-cookies enable
}
interfaces {
    bridge br0 {
        address 192.168.59.1/24
        aging 300
        bridged-conntrack disable
        description "Local Bridge"
        hello-time 2
        max-age 20
        priority 32768
        promiscuous enable
        stp false
    }
    ethernet eth0 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth1 {
        address 203.0.113.89/27
        address 2001:db8:99::59/64
        description Internet
        duplex auto
        firewall {
            in {
                ipv6-name WANv6_IN
                name WAN_IN
            }
            local {
                ipv6-name WANv6_LOCAL
                name WAN_LOCAL
            }
        }
        ip {
            enable-proxy-arp
        }
        speed auto
    }
    ethernet eth2 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth3 {
        address 2001:db8:99:5930::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5930::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth4 {
        address 2001:db8:99:5940::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5940::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth5 {
        address 2001:db8:99:5950::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5950::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth6 {
        address 2001:db8:99:5960::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5960::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth7 {
        address 2001:db8:99:5970::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5970::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    ethernet eth8 {
        address 2001:db8:99:5980::1/64
        duplex auto
        ip {
            enable-proxy-arp
        }
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2606:4700:4700::1111
                name-server 2606:4700:4700::1001
                other-config-flag false
                prefix 2001:db8:99:5980::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
        speed auto
    }
    loopback lo {
    }
    openvpn vtun1 {
        config-file /config/tst-pre.ovpn
    }
}
protocols {
    static {
        interface-route 203.0.113.91/32 {
            next-hop-interface eth3 {
            }
        }
        interface-route 203.0.113.92/32 {
            next-hop-interface eth6 {
            }
        }
        route6 2001:db8:99:59::/64 {
            blackhole {
            }
        }
        route6 2001:db8:99:5900::/56 {
            blackhole {
            }
        }
        route6 ::/0 {
            next-hop 2001:db8:99::1 {
                interface eth1
            }
        }
    }
}
service {
    dhcp-server {
        disabled false
        hostfile-update disable
        shared-network-name LAN_BR {
            authoritative enable
            subnet 192.168.59.0/24 {
                default-router 192.168.59.1
                dns-server 192.168.59.1
                lease 86400
                start 192.168.59.38 {
                    stop 192.168.59.243
                }
            }
        }
        static-arp disable
        use-dnsmasq disable
    }
    dns {
        forwarding {
            cache-size 10000
            force-public-dns-boost
            listen-on br0
        }
    }
    gui {
        http-port 80
        https-port 443
        older-ciphers disable
    }
    nat {
        rule 100 {
            description "warp edge-5 enp33s0f1np1 forward 8022 to 22 tcp"
            destination {
                address 203.0.113.91
                port 8022
            }
            inbound-interface eth1
            inside-address {
                address 203.0.113.91
                port 22
            }
            log disable
            protocol tcp
            type destination
        }
        rule 5001 {
            description "masquerade for WAN"
            log disable
            outbound-interface eth1
            protocol all
            type masquerade
        }
    }
    ssh {
        disable-password-authentication
        port 22
        protocol-version v2
    }
    unms {
        connection wss://example.uisp.com:443+SCRUBBEDUISPKEYBBBB+allowUntrustedCertificate
    }
}
system {
    analytics-handler {
        send-analytics-report false
    }
    conntrack {
        hash-size 131072
        modules {
            ftp {
                disable
            }
            gre {
                disable
            }
            h323 {
                disable
            }
            pptp {
                disable
            }
            sip {
                disable
            }
            tftp {
                disable
            }
        }
        table-size 1048576
    }
    crash-handler {
        send-crash-report false
    }
    gateway-address 203.0.113.65
    host-name r-us-tst-5-9
    login {
        user audit {
            authentication {
                encrypted-password $5$AUDITSALT$AUDITHASH
            }
            level operator
        }
        user ubnt {
            authentication {
                encrypted-password $5$OTHERSALT$OTHERHASH
                public-keys fleet-2025.7.28 {
                    key AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEtest
                    type ecdsa-sha2-nistp521
                }
            }
            level admin
        }
    }
    name-server 1.1.1.1
    name-server 2606:4700:4700::1111
    name-server 2606:4700:4700::1001
    ntp {
        server 0.ubnt.pool.ntp.org {
        }
        server 1.ubnt.pool.ntp.org {
        }
        server 2.ubnt.pool.ntp.org {
        }
        server 3.ubnt.pool.ntp.org {
        }
    }
    offload {
        ipv4 {
            forwarding enable
        }
        ipv6 {
            forwarding enable
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone UTC
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:suspend@1:system@5:ubnt-l2tp@1:ubnt-pptp@1:ubnt-udapi-server@1:ubnt-unms@2:ubnt-util@1:vrrp@1:vyatta-netflow@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v3.0.1.5862409.250924.1408 */
