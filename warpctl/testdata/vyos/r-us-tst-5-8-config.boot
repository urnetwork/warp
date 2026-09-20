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
            description "warp edge-3 eno1np0 lb 53 udp"
            destination {
                address 2001:db8:99:5880:e643:4bff:fe94:e380
                port 53
            }
            log disable
            protocol udp
        }
        rule 110 {
            action accept
            description "warp edge-3 eno1np0 lb 80 tcp"
            destination {
                address 2001:db8:99:5880:e643:4bff:fe94:e380
                port 80
            }
            log disable
            protocol tcp
        }
        rule 120 {
            action accept
            description "warp edge-3 eno1np0 lb 443"
            destination {
                address 2001:db8:99:5880:e643:4bff:fe94:e380
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp edge-3 eno1np0 lb 444 tcp"
            destination {
                address 2001:db8:99:5880:e643:4bff:fe94:e380
                port 444
            }
            log disable
            protocol tcp
        }
        rule 140 {
            action accept
            description "warp edge-3 eno1np0 lb 1080 tcp"
            destination {
                address 2001:db8:99:5880:e643:4bff:fe94:e380
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp edge-3 eno2np1 lb 53 udp"
            destination {
                address 2001:db8:99:5860:e643:4bff:fe94:e381
                port 53
            }
            log disable
            protocol udp
        }
        rule 160 {
            action accept
            description "warp edge-3 eno2np1 lb 80 tcp"
            destination {
                address 2001:db8:99:5860:e643:4bff:fe94:e381
                port 80
            }
            log disable
            protocol tcp
        }
        rule 170 {
            action accept
            description "warp edge-3 eno2np1 lb 443"
            destination {
                address 2001:db8:99:5860:e643:4bff:fe94:e381
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp edge-3 eno2np1 lb 444 tcp"
            destination {
                address 2001:db8:99:5860:e643:4bff:fe94:e381
                port 444
            }
            log disable
            protocol tcp
        }
        rule 190 {
            action accept
            description "warp edge-3 eno2np1 lb 1080 tcp"
            destination {
                address 2001:db8:99:5860:e643:4bff:fe94:e381
                port 1080
            }
            log disable
            protocol tcp
        }
    }
    ipv6-name WANv6_LOCAL {
        default-action drop
        description "WAN inbound traffic to the router"
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
            description "Allow icmp"
            log disable
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
            description "warp edge-3 eno1np0 lb 53 udp"
            destination {
                address 203.0.113.84
                port 53
            }
            log disable
            protocol udp
        }
        rule 110 {
            action accept
            description "warp edge-3 eno1np0 lb 80 tcp"
            destination {
                address 203.0.113.84
                port 80
            }
            log disable
            protocol tcp
        }
        rule 120 {
            action accept
            description "warp edge-3 eno1np0 lb 443"
            destination {
                address 203.0.113.84
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp edge-3 eno1np0 lb 444 tcp"
            destination {
                address 203.0.113.84
                port 444
            }
            log disable
            protocol tcp
        }
        rule 140 {
            action accept
            description "warp edge-3 eno1np0 lb 1080 tcp"
            destination {
                address 203.0.113.84
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp edge-3 eno2np1 lb 53 udp"
            destination {
                address 203.0.113.85
                port 53
            }
            log disable
            protocol udp
        }
        rule 160 {
            action accept
            description "warp edge-3 eno2np1 lb 80 tcp"
            destination {
                address 203.0.113.85
                port 80
            }
            log disable
            protocol tcp
        }
        rule 170 {
            action accept
            description "warp edge-3 eno2np1 lb 443"
            destination {
                address 203.0.113.85
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp edge-3 eno2np1 lb 444 tcp"
            destination {
                address 203.0.113.85
                port 444
            }
            log disable
            protocol tcp
        }
        rule 190 {
            action accept
            description "warp edge-3 eno2np1 lb 1080 tcp"
            destination {
                address 203.0.113.85
                port 1080
            }
            log disable
            protocol tcp
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
            description "Allow icmp"
            log disable
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
        address 192.168.58.1/24
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
        address 203.0.113.81/27
        address 2001:db8:99::58/48
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
        address 2001:db8:99:5830::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5830::/64 {
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
        address 2001:db8:99:5840::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5840::/64 {
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
        address 2001:db8:99:5850::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5850::/64 {
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
        address 2001:db8:99:5860::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5860::/64 {
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
        address 2001:db8:99:5870::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5870::/64 {
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
        address 2001:db8:99:5880::1/64
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
                other-config-flag false
                prefix 2001:db8:99:5880::/64 {
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
        config-file /config/by-pre.ovpn
    }
}
protocols {
    static {
        interface-route 203.0.113.84/32 {
            next-hop-interface eth8 {
            }
        }
        interface-route 203.0.113.85/32 {
            next-hop-interface eth6 {
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
            subnet 192.168.58.0/24 {
                default-router 192.168.58.1
                dns-server 192.168.58.1
                lease 86400
                start 192.168.58.38 {
                    stop 192.168.58.243
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
                address 203.0.113.64/27
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
        connection wss://example.uisp.com:443+SCRUBBEDUISPKEYAAAA+allowUntrustedCertificate
    }
}
system {
    analytics-handler {
        send-analytics-report true
    }
    conntrack {
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
    }
    crash-handler {
        send-crash-report true
    }
    gateway-address 203.0.113.65
    host-name r-us-tst-5-8
    login {
        user ubnt {
            authentication {
                encrypted-password $5$SCRUBBEDSALT$SCRUBBEDHASH
                public-keys fleet-2025.7.28 {
                    key AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAEtest
                    type ecdsa-sha2-nistp521
                }
            }
            level admin
        }
    }
    name-server 1.1.1.1
    name-server 9.9.9.9
    name-server 2606:4700:4700::1111
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
