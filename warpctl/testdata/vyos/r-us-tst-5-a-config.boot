firewall {
    all-ping enable
    broadcast-ping disable
    group {
        ipv6-network-group BOGONS6 {
            description "Sources that never arrive from the isp"
            ipv6-network 2001:db8:a4::/48
            ipv6-network ::/127
            ipv6-network ::ffff:0:0/96
            ipv6-network 100::/64
            ipv6-network 2001:2::/48
            ipv6-network 2001:db8::/32
            ipv6-network 3ffe::/16
            ipv6-network fc00::/7
            ipv6-network fe80::/10
            ipv6-network fec0::/10
            ipv6-network ff00::/8
        }
        network-group BOGONS {
            description "Sources that never arrive from the isp"
            network 198.51.100.96/27
            network 0.0.0.0/8
            network 10.0.0.0/8
            network 100.64.0.0/10
            network 127.0.0.0/8
            network 169.254.0.0/16
            network 172.16.0.0/12
            network 192.0.0.0/24
            network 192.0.2.0/24
            network 192.168.0.0/16
            network 198.18.0.0/15
            network 198.51.100.0/24
            network 203.0.113.0/24
            network 224.0.0.0/4
            network 240.0.0.0/4
        }
    }
    ipv6-name WANv6_IN {
        default-action drop
        description "ISP to the hosts"
        rule 5 {
            action drop
            description "Drop bogon sources"
            log disable
            protocol all
            source {
                group {
                    ipv6-network-group BOGONS6
                }
            }
        }
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
        rule 40 {
            action accept
            description "Allow icmp"
            log disable
            protocol ipv6-icmp
        }
        rule 100 {
            action accept
            description "warp edge-7 eno2np1 lb 53 udp"
            destination {
                address 2001:db8:a4:5a50:200:5eff:fe00:5372
                port 53
            }
            log disable
            protocol udp
        }
        rule 110 {
            action accept
            description "warp edge-7 eno2np1 lb 80 tcp"
            destination {
                address 2001:db8:a4:5a50:200:5eff:fe00:5372
                port 80
            }
            log disable
            protocol tcp
        }
        rule 120 {
            action accept
            description "warp edge-7 eno2np1 lb 443"
            destination {
                address 2001:db8:a4:5a50:200:5eff:fe00:5372
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp edge-7 eno2np1 lb 444 tcp"
            destination {
                address 2001:db8:a4:5a50:200:5eff:fe00:5372
                port 444
            }
            log disable
            protocol tcp
        }
        rule 140 {
            action accept
            description "warp edge-7 eno2np1 lb 1080 tcp"
            destination {
                address 2001:db8:a4:5a50:200:5eff:fe00:5372
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp edge-7 eno3np2 lb 53 udp"
            destination {
                address 2001:db8:a4:5a60:200:5eff:fe00:5373
                port 53
            }
            log disable
            protocol udp
        }
        rule 160 {
            action accept
            description "warp edge-7 eno3np2 lb 80 tcp"
            destination {
                address 2001:db8:a4:5a60:200:5eff:fe00:5373
                port 80
            }
            log disable
            protocol tcp
        }
        rule 170 {
            action accept
            description "warp edge-7 eno3np2 lb 443"
            destination {
                address 2001:db8:a4:5a60:200:5eff:fe00:5373
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp edge-7 eno3np2 lb 444 tcp"
            destination {
                address 2001:db8:a4:5a60:200:5eff:fe00:5373
                port 444
            }
            log disable
            protocol tcp
        }
        rule 190 {
            action accept
            description "warp edge-7 eno3np2 lb 1080 tcp"
            destination {
                address 2001:db8:a4:5a60:200:5eff:fe00:5373
                port 1080
            }
            log disable
            protocol tcp
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
        description "ISP to the router"
        rule 1 {
            action accept
            description "Allow local neighbor discovery"
            icmpv6 {
                type 133
            }
            log disable
            protocol ipv6-icmp
        }
        rule 2 {
            action accept
            description "Allow local neighbor discovery"
            icmpv6 {
                type 134
            }
            log disable
            protocol ipv6-icmp
        }
        rule 3 {
            action accept
            description "Allow local neighbor discovery"
            icmpv6 {
                type 135
            }
            log disable
            protocol ipv6-icmp
        }
        rule 4 {
            action accept
            description "Allow local neighbor discovery"
            icmpv6 {
                type 136
            }
            log disable
            protocol ipv6-icmp
        }
        rule 5 {
            action accept
            description "Allow link local icmp control"
            icmpv6 {
                type 1
            }
            log disable
            protocol ipv6-icmp
            source {
                address fe80::/10
            }
        }
        rule 6 {
            action accept
            description "Allow link local icmp control"
            icmpv6 {
                type 2
            }
            log disable
            protocol ipv6-icmp
            source {
                address fe80::/10
            }
        }
        rule 7 {
            action accept
            description "Allow link local icmp control"
            icmpv6 {
                type 3
            }
            log disable
            protocol ipv6-icmp
            source {
                address fe80::/10
            }
        }
        rule 8 {
            action accept
            description "Allow link local icmp control"
            icmpv6 {
                type 4
            }
            log disable
            protocol ipv6-icmp
            source {
                address fe80::/10
            }
        }
        rule 9 {
            action accept
            description "Allow link local icmp control"
            icmpv6 {
                type 130
            }
            log disable
            protocol ipv6-icmp
            source {
                address fe80::/10
            }
        }
        rule 10 {
            action drop
            description "Drop bogon sources"
            log disable
            protocol all
            source {
                group {
                    ipv6-network-group BOGONS6
                }
            }
        }
        rule 11 {
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
        description "ISP to the hosts"
        rule 4 {
            action accept
            description "Allow icmp from the isp gateway"
            log disable
            protocol icmp
            source {
                address 198.51.100.97
            }
        }
        rule 5 {
            action drop
            description "Drop bogon sources"
            log disable
            protocol all
            source {
                group {
                    network-group BOGONS
                }
            }
        }
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
        rule 40 {
            action accept
            description "Allow icmp"
            log disable
            protocol icmp
        }
        rule 100 {
            action accept
            description "warp edge-7 eno2np1 lb 53 udp"
            destination {
                address 198.51.100.99
                port 53
            }
            log disable
            protocol udp
        }
        rule 110 {
            action accept
            description "warp edge-7 eno2np1 lb 80 tcp"
            destination {
                address 198.51.100.99
                port 80
            }
            log disable
            protocol tcp
        }
        rule 120 {
            action accept
            description "warp edge-7 eno2np1 lb 443"
            destination {
                address 198.51.100.99
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp edge-7 eno2np1 lb 444 tcp"
            destination {
                address 198.51.100.99
                port 444
            }
            log disable
            protocol tcp
        }
        rule 140 {
            action accept
            description "warp edge-7 eno2np1 lb 1080 tcp"
            destination {
                address 198.51.100.99
                port 1080
            }
            log disable
            protocol tcp
        }
        rule 150 {
            action accept
            description "warp edge-7 eno3np2 lb 53 udp"
            destination {
                address 198.51.100.100
                port 53
            }
            log disable
            protocol udp
        }
        rule 160 {
            action accept
            description "warp edge-7 eno3np2 lb 80 tcp"
            destination {
                address 198.51.100.100
                port 80
            }
            log disable
            protocol tcp
        }
        rule 170 {
            action accept
            description "warp edge-7 eno3np2 lb 443"
            destination {
                address 198.51.100.100
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp edge-7 eno3np2 lb 444 tcp"
            destination {
                address 198.51.100.100
                port 444
            }
            log disable
            protocol tcp
        }
        rule 190 {
            action accept
            description "warp edge-7 eno3np2 lb 1080 tcp"
            destination {
                address 198.51.100.100
                port 1080
            }
            log disable
            protocol tcp
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
        description "ISP to the router"
        rule 4 {
            action accept
            description "Allow icmp from the isp gateway"
            log disable
            protocol icmp
            source {
                address 198.51.100.97
            }
        }
        rule 5 {
            action drop
            description "Drop bogon sources"
            log disable
            protocol all
            source {
                group {
                    network-group BOGONS
                }
            }
        }
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
        address 192.168.204.1/24
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
        address 198.51.100.98/27
        address 2001:db8:a2:2::2/126
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
        address 2001:db8:a4:5a30::1/64
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
                prefix 2001:db8:a4:5a30::/64 {
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
        address 2001:db8:a4:5a40::1/64
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
                prefix 2001:db8:a4:5a40::/64 {
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
        address 2001:db8:a4:5a50::1/64
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
                prefix 2001:db8:a4:5a50::/64 {
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
        address 2001:db8:a4:5a60::1/64
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
                prefix 2001:db8:a4:5a60::/64 {
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
        address 2001:db8:a4:5a70::1/64
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
                prefix 2001:db8:a4:5a70::/64 {
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
        address 2001:db8:a4:5a80::1/64
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
                prefix 2001:db8:a4:5a80::/64 {
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
        interface-route 198.51.100.99/32 {
            next-hop-interface eth5 {
            }
        }
        interface-route 198.51.100.100/32 {
            next-hop-interface eth6 {
            }
        }
        route6 2001:db8:a4::/48 {
            blackhole {
            }
        }
        route6 ::/0 {
            next-hop 2001:db8:a2:2::1 {
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
            subnet 192.168.204.0/24 {
                default-router 192.168.204.1
                dns-server 192.168.204.1
                lease 86400
                start 192.168.204.38 {
                    stop 192.168.204.243
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
        rule 5000 {
            description "Exclude local"
            exclude
            log disable
            outbound-interface eth1
            protocol all
            source {
                address 198.51.100.96/27
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
        disable-password-authentication
        port 22
        protocol-version v2
    }
    unms {
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
    gateway-address 198.51.100.97
    host-name r-us-tst-5-a
    login {
        user ubnt {
            authentication {
                encrypted-password $5$TENSALT$TENHASH
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
    offload {
        ipv4 {
            forwarding enable
        }
        ipv6 {
            forwarding disable
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
