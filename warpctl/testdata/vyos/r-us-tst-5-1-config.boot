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
        rule 40 {
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
        rule 40 {
            action accept
            description "Allow icmp"
            log disable
            protocol icmp
        }
        rule 100 {
            action accept
            description "warp edge-2 backup ssh"
            destination {
                address 192.168.51.43
                port 22
            }
            log disable
            protocol tcp
        }
        rule 110 {
            action accept
            description "warp edge-6 backup ssh redis"
            destination {
                address 192.168.51.193
                port 22
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
        address 192.168.51.1/24
        address 2001:db8:99:5100::1/64
        aging 300
        bridged-conntrack disable
        description "Local Bridge"
        hello-time 2
        ipv6 {
            dup-addr-detect-transmits 1
            router-advert {
                cur-hop-limit 64
                link-mtu 0
                managed-flag false
                max-interval 600
                name-server 2001:db8:99:5100::1
                other-config-flag false
                prefix 2001:db8:99:5100::/64 {
                    autonomous-flag true
                    on-link-flag true
                    valid-lifetime 2592000
                }
                reachable-time 0
                retrans-timer 0
                send-advert true
            }
        }
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
        address 203.0.113.73/27
        address 2001:db8:99::51/64
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
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth4 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth5 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth6 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth7 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
        speed auto
    }
    ethernet eth8 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
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
        route6 2001:db8:99:51::/64 {
            blackhole {
            }
        }
        route6 2001:db8:99:5100::/56 {
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
            subnet 192.168.51.0/24 {
                default-router 192.168.51.1
                dns-server 192.168.51.1
                lease 86400
                start 192.168.51.38 {
                    stop 192.168.51.243
                }
                static-mapping builder {
                    ip-address 192.168.51.176
                    mac-address 9c:76:0e:4a:10:e2
                }
                static-mapping edge-2 {
                    ip-address 192.168.51.43
                    mac-address e4:43:4b:56:79:10
                }
                static-mapping edge-3 {
                    ip-address 192.168.51.180
                    mac-address 6c:fe:54:2d:f2:f1
                }
                static-mapping edge-6 {
                    ip-address 192.168.51.193
                    mac-address 48:df:37:7a:71:58
                }
                static-mapping fireside {
                    ip-address 192.168.51.196
                    mac-address 38:05:25:35:47:3f
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
            description "warp edge-2 backup ssh"
            destination {
                port 8022
            }
            inbound-interface eth1
            inside-address {
                address 192.168.51.43
                port 22
            }
            log disable
            protocol tcp
            type destination
        }
        rule 110 {
            description "warp edge-6 backup ssh redis"
            destination {
                port 8023
            }
            inbound-interface eth1
            inside-address {
                address 192.168.51.193
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
        connection wss://example.uisp.com:443+SCRUBBEDUISPKEYLAN+allowUntrustedCertificate
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
    host-name r-us-tst-5-1
    login {
        user ubnt {
            authentication {
                encrypted-password $5$LANSALT$LANHASH
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
