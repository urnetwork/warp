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
                address 2001:db8:535::/48
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
        rule 30 {
            action accept
            description "Allow local"
            log disable
            protocol all
            source {
                address 192.0.2.192/27
            }
        }
        rule 40 {
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
        address 192.168.53.1/24
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
        address 2001:db8:535:5300::1/64
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
                prefix 2001:db8:535:5300::/64 {
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
    ethernet eth1 {
        bridge-group {
            bridge br0
        }
        description "Local Bridge"
        duplex auto
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
        address 192.0.2.195/27
        address 2001:db8:535::53/64
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
    loopback lo {
    }
    openvpn vtun1 {
        config-file /config/by-pre.ovpn
    }
}
protocols {
    static {
        route6 2001:db8:535:53::/64 {
            blackhole {
            }
        }
        route6 2001:db8:535:5300::/56 {
            blackhole {
            }
        }
        route6 ::/0 {
            next-hop 2001:db8:535::1 {
                interface eth3
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
            subnet 192.168.53.0/24 {
                default-router 192.168.53.1
                dns-server 192.168.53.1
                lease 86400
                start 192.168.53.38 {
                    stop 192.168.53.243
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
            outbound-interface eth3
            protocol all
            source {
                address 192.0.2.192/27
            }
            type masquerade
        }
        rule 5001 {
            description "masquerade for WAN"
            log disable
            outbound-interface eth3
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
        send-crash-report false
    }
    gateway-address 192.0.2.193
    host-name r-us-tst-5-3
    login {
        user ubnt {
            authentication {
                encrypted-password $5$THREESALT$THREEHASH
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
