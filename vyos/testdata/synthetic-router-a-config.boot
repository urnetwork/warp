firewall {
    all-ping enable
    broadcast-ping disable
    ipv6-name WANv6_IN {
        default-action drop
        description "WAN inbound traffic forwarded to LAN"
        enable-default-log
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
            description "Allow tcp/udp 443"
            destination {
                address 2001:db8::10
                port 443
            }
            protocol tcp_udp
        }
        rule 31 {
            action accept
            description "Allow tcp/udp 80"
            destination {
                address 2001:db8::10
                port 80
            }
            protocol tcp_udp
        }
        rule 32 {
            action accept
            description "Allow local"
            source {
                address 2001:db8::1/48
            }
        }
        rule 33 {
            action accept
            destination {
                address 2001:db8::a
                port 80
            }
            protocol tcp_udp
        }
        rule 34 {
            action accept
            destination {
                address 2001:db8::a
                port 443
            }
            protocol tcp_udp
        }
        rule 35 {
            action accept
            destination {
                address 2001:db8::d
                port 80
            }
            protocol tcp_udp
        }
        rule 36 {
            action accept
            destination {
                address 2001:db8::d
                port 443
            }
            protocol tcp_udp
        }
        rule 37 {
            action accept
            destination {
                address 2001:db8::7
                port 80
            }
            protocol tcp_udp
        }
        rule 38 {
            action accept
            destination {
                address 2001:db8::7
                port 443
            }
            protocol tcp_udp
        }
        rule 39 {
            action accept
            destination {
                address 2001:db8::d
                port 444
            }
            protocol tcp_udp
        }
        rule 40 {
            action accept
            destination {
                address 2001:db8::d
                port 1080
            }
            protocol tcp_udp
        }
        rule 41 {
            action accept
            destination {
                address 2001:db8::10
                port 444
            }
            protocol tcp_udp
        }
        rule 42 {
            action accept
            destination {
                address 2001:db8::10
                port 1080
            }
            protocol tcp_udp
        }
        rule 50 {
            action accept
            protocol ipv6-icmp
        }
    }
    ipv6-name WANv6_LOCAL {
        default-action drop
        description "WAN inbound traffic to the router"
        enable-default-log
        rule 10 {
            action accept
            description "Allow established/related sessions"
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
        rule 50 {
            action accept
            protocol ipv6-icmp
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
            action accept
            description "Allow local"
            destination {
            }
            log disable
            protocol all
            source {
                address 192.0.2.6/27
            }
        }
        rule 30 {
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 40 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno3 http"
            destination {
                address 192.0.2.11
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 50 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno3 https"
            destination {
                address 192.0.2.11
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 60 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno4 http"
            destination {
                address 192.0.2.12
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 70 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno4 https"
            destination {
                address 192.0.2.12
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 80 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno3 http"
            destination {
                address 192.0.2.10
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 90 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno3 https"
            destination {
                address 192.0.2.10
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 100 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno4 http"
            destination {
                address 192.0.2.9
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 110 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno4 https"
            destination {
                address 192.0.2.9
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 120 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno4 https proxy"
            destination {
                address 192.0.2.12
                port 444
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno4 socks"
            destination {
                address 192.0.2.12
                port 1080
            }
            log disable
            protocol tcp_udp
        }
        rule 140 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno3 https proxy"
            destination {
                address 192.0.2.11
                port 444
            }
            log disable
            protocol tcp_udp
        }
        rule 150 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno3 socks"
            destination {
                address 192.0.2.11
                port 1080
            }
            log disable
            protocol tcp_udp
        }
        rule 160 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno4 https proxy"
            destination {
                address 192.0.2.9
                port 444
            }
            log disable
            protocol tcp_udp
        }
        rule 170 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno4 socks"
            destination {
                address 192.0.2.9
                port 1080
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno3 https proxy"
            destination {
                address 192.0.2.10
                port 444
            }
            log disable
            protocol tcp_udp
        }
        rule 190 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno3 socks"
            destination {
                address 192.0.2.10
                port 1080
            }
            log disable
            protocol tcp_udp
        }
        rule 200 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno3 dns"
            destination {
                address 192.0.2.11
                port 53
            }
            log disable
            protocol tcp_udp
        }
        rule 210 {
            action accept
            description "warp synthetic-us-fmt-5-edge-3 eno4 dns"
            destination {
                address 192.0.2.12
                port 53
            }
            log disable
            protocol tcp_udp
        }
        rule 220 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno3 dns"
            destination {
                address 192.0.2.10
                port 53
            }
            log disable
            protocol tcp_udp
        }
        rule 230 {
            action accept
            description "warp synthetic-us-fmt-5-edge-4 eno4 dns"
            destination {
                address 192.0.2.9
                port 53
            }
            log disable
            protocol tcp_udp
        }
        rule 240 {
            action accept
            log disable
            protocol icmp
        }
        rule 250 {
            action accept
            protocol tcp_udp
            source {
                address 192.0.2.6/27
            }
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
        rule 50 {
            action accept
            protocol icmp
        }
    }
    receive-redirects disable
    send-redirects enable
    source-validation disable
    syn-cookies enable
}
interfaces {
    bridge br0 {
        address 192.0.2.18/24
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
        address 192.0.2.8/27
        address 2001:db8::3/48
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
        duplex auto
        ip {
            enable-proxy-arp
        }
        speed auto
    }
    ethernet eth4 {
        duplex auto
        ip {
            enable-proxy-arp
        }
        speed auto
    }
    ethernet eth5 {
        address 2001:db8::6/64
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
                name-server 2001:db8::1f
                other-config-flag false
                prefix 2001:db8::5/64 {
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
        address 2001:db8::9/64
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
                name-server 2001:db8::1f
                other-config-flag false
                prefix 2001:db8::8/64 {
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
        address 2001:db8::c/64
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
                name-server 2001:db8::1f
                other-config-flag false
                prefix 2001:db8::b/64 {
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
        address 2001:db8::f/64
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
                name-server 2001:db8::1f
                other-config-flag false
                prefix 2001:db8::e/64 {
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
        config-file /config/synthetic-pre.ovpn
    }
}
protocols {
    static {
        interface-route 192.0.2.9/32 {
            next-hop-interface eth7 {
            }
        }
        interface-route 192.0.2.10/32 {
            next-hop-interface eth5 {
            }
        }
        interface-route 192.0.2.11/32 {
            next-hop-interface eth8 {
            }
        }
        interface-route 192.0.2.12/32 {
            next-hop-interface eth6 {
            }
        }
        route6 ::/0 {
            next-hop 2001:db8::2 {
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
            subnet 192.0.2.17/24 {
                default-router 192.0.2.18
                dns-server 192.0.2.18
                lease 86400
                start 192.0.2.19 {
                    stop 192.0.2.20
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
        older-ciphers enable
    }
    nat {
        rule 5000 {
            description "Exclude local"
            exclude
            log disable
            outbound-interface eth1
            protocol all
            source {
                address 192.0.2.6/29
            }
            type masquerade
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
        port 22
        protocol-version v2
    }
    unms {
        connection wss://controller.synthetic.example:443+synthetic-key+allowUntrustedCert
    }
}
system {
    analytics-handler {
        send-analytics-report true
    }
    crash-handler {
        send-crash-report true
    }
    gateway-address 192.0.2.7
    host-name synthetic-router-a
    login {
        user synthetic-admin {
            authentication {
                encrypted-password $5$synthetic$not-a-password
            }
            level admin
        }
    }
    name-server 192.0.2.1
    name-server 192.0.2.2
    name-server 2001:db8::1f
    ntp {
        server synthetic-server-1.example {
        }
        server synthetic-server-2.example {
        }
        server synthetic-server-3.example {
        }
        server synthetic-server-4.example {
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
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:suspend@1:system@5:synthetic-admin-l2tp@1:synthetic-admin-pptp@1:synthetic-admin-udapi-server@1:synthetic-admin-unms@2:synthetic-admin-util@1:vrrp@1:vyatta-netflow@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v3.0.1.5862409.250924.1408 */
