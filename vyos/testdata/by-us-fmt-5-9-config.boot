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
        rule 50 {
            action accept
            description "Allow icmp"
            protocol ipv6-icmp
        }
        rule 60 {
            action accept
            destination {
                address 2001:470:99:5930:9a03:9bff:fe56:593
                port 80
            }
            protocol tcp_udp
        }
        rule 61 {
            action accept
            destination {
                address 2001:470:99:5930:9a03:9bff:fe56:593
                port 443
            }
            protocol tcp_udp
        }
        rule 62 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 80
            }
            protocol tcp_udp
        }
        rule 63 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 443
            }
            protocol tcp_udp
        }
        rule 64 {
            action accept
            destination {
                address 2001:470:99:5960:4adf:37ff:fe9a:32d8
                port 80
            }
            protocol tcp_udp
        }
        rule 65 {
            action accept
            destination {
                address 2001:470:99:5960:4adf:37ff:fe9a:32d8
                port 443
            }
            protocol tcp_udp
        }
        rule 66 {
            action accept
            destination {
                address 2001:470:99:5930:9a03:9bff:fe56:593
                port 444
            }
            protocol tcp_udp
        }
        rule 67 {
            action accept
            destination {
                address 2001:470:99:5930:9a03:9bff:fe56:593
                port 1080
            }
            protocol tcp_udp
        }
        rule 70 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7117
            }
            protocol tcp_udp
        }
        rule 71 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7118
            }
            protocol tcp_udp
        }
        rule 72 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7119
            }
            protocol tcp_udp
        }
        rule 73 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7120
            }
            protocol tcp_udp
        }
        rule 74 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7121
            }
            protocol tcp_udp
        }
        rule 80 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7123
            }
            protocol tcp_udp
        }
        rule 81 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7124
            }
            protocol tcp_udp
        }
        rule 82 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7125
            }
            protocol tcp_udp
        }
        rule 83 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7126
            }
            protocol tcp_udp
        }
        rule 84 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7127
            }
            protocol tcp_udp
        }
        rule 90 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7129
            }
            protocol tcp_udp
        }
        rule 91 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7130
            }
            protocol tcp_udp
        }
        rule 92 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7131
            }
            protocol tcp_udp
        }
        rule 93 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7132
            }
            protocol tcp_udp
        }
        rule 94 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7133
            }
            protocol tcp_udp
        }
        rule 100 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7135
            }
            protocol tcp_udp
        }
        rule 101 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7136
            }
            protocol tcp_udp
        }
        rule 102 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7137
            }
            protocol tcp_udp
        }
        rule 103 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7138
            }
            protocol tcp_udp
        }
        rule 104 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7139
            }
            protocol tcp_udp
        }
        rule 110 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7141
            }
            protocol tcp_udp
        }
        rule 111 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7142
            }
            protocol tcp_udp
        }
        rule 112 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7143
            }
            protocol tcp_udp
        }
        rule 113 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7144
            }
            protocol tcp_udp
        }
        rule 114 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7145
            }
            protocol tcp_udp
        }
        rule 120 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7147
            }
            protocol tcp_udp
        }
        rule 121 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7148
            }
            protocol tcp_udp
        }
        rule 122 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7149
            }
            protocol tcp_udp
        }
        rule 123 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7150
            }
            protocol tcp_udp
        }
        rule 124 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7151
            }
            protocol tcp_udp
        }
        rule 130 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7153
            }
            protocol tcp_udp
        }
        rule 131 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7154
            }
            protocol tcp_udp
        }
        rule 132 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7155
            }
            protocol tcp_udp
        }
        rule 133 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7156
            }
            protocol tcp_udp
        }
        rule 134 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7157
            }
            protocol tcp_udp
        }
        rule 140 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7159
            }
            protocol tcp_udp
        }
        rule 141 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7160
            }
            protocol tcp_udp
        }
        rule 142 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7161
            }
            protocol tcp_udp
        }
        rule 143 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7162
            }
            protocol tcp_udp
        }
        rule 144 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7163
            }
            protocol tcp_udp
        }
        rule 150 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7165
            }
            protocol tcp_udp
        }
        rule 151 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7166
            }
            protocol tcp_udp
        }
        rule 152 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7167
            }
            protocol tcp_udp
        }
        rule 153 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7168
            }
            protocol tcp_udp
        }
        rule 154 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7169
            }
            protocol tcp_udp
        }
        rule 160 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7171
            }
            protocol tcp_udp
        }
        rule 161 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7172
            }
            protocol tcp_udp
        }
        rule 162 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7173
            }
            protocol tcp_udp
        }
        rule 163 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7174
            }
            protocol tcp_udp
        }
        rule 164 {
            action accept
            destination {
                address 2001:470:99:5960:3a05:25ff:fe32:e5ab
                port 7175
            }
            protocol tcp_udp
        }
        rule 270 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7117
            }
            protocol tcp_udp
        }
        rule 271 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7118
            }
            protocol tcp_udp
        }
        rule 272 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7119
            }
            protocol tcp_udp
        }
        rule 273 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7120
            }
            protocol tcp_udp
        }
        rule 274 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7121
            }
            protocol tcp_udp
        }
        rule 280 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7123
            }
            protocol tcp_udp
        }
        rule 281 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7124
            }
            protocol tcp_udp
        }
        rule 282 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7125
            }
            protocol tcp_udp
        }
        rule 283 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7126
            }
            protocol tcp_udp
        }
        rule 284 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7127
            }
            protocol tcp_udp
        }
        rule 290 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7129
            }
            protocol tcp_udp
        }
        rule 291 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7130
            }
            protocol tcp_udp
        }
        rule 292 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7131
            }
            protocol tcp_udp
        }
        rule 293 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7132
            }
            protocol tcp_udp
        }
        rule 294 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7133
            }
            protocol tcp_udp
        }
        rule 300 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7135
            }
            protocol tcp_udp
        }
        rule 301 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7136
            }
            protocol tcp_udp
        }
        rule 302 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7137
            }
            protocol tcp_udp
        }
        rule 303 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7138
            }
            protocol tcp_udp
        }
        rule 304 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7139
            }
            protocol tcp_udp
        }
        rule 310 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7141
            }
            protocol tcp_udp
        }
        rule 311 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7142
            }
            protocol tcp_udp
        }
        rule 312 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7143
            }
            protocol tcp_udp
        }
        rule 313 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7144
            }
            protocol tcp_udp
        }
        rule 314 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7145
            }
            protocol tcp_udp
        }
        rule 320 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7147
            }
            protocol tcp_udp
        }
        rule 321 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7148
            }
            protocol tcp_udp
        }
        rule 322 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7149
            }
            protocol tcp_udp
        }
        rule 323 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7150
            }
            protocol tcp_udp
        }
        rule 324 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7151
            }
            protocol tcp_udp
        }
        rule 330 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7153
            }
            protocol tcp_udp
        }
        rule 331 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7154
            }
            protocol tcp_udp
        }
        rule 332 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7155
            }
            protocol tcp_udp
        }
        rule 333 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7156
            }
            protocol tcp_udp
        }
        rule 334 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7157
            }
            protocol tcp_udp
        }
        rule 340 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7159
            }
            protocol tcp_udp
        }
        rule 341 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7160
            }
            protocol tcp_udp
        }
        rule 342 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7161
            }
            protocol tcp_udp
        }
        rule 343 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7162
            }
            protocol tcp_udp
        }
        rule 344 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7163
            }
            protocol tcp_udp
        }
        rule 350 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7165
            }
            protocol tcp_udp
        }
        rule 351 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7166
            }
            protocol tcp_udp
        }
        rule 352 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7167
            }
            protocol tcp_udp
        }
        rule 353 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7168
            }
            protocol tcp_udp
        }
        rule 354 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7169
            }
            protocol tcp_udp
        }
        rule 360 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7171
            }
            protocol tcp_udp
        }
        rule 361 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7172
            }
            protocol tcp_udp
        }
        rule 362 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7173
            }
            protocol tcp_udp
        }
        rule 363 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7174
            }
            protocol tcp_udp
        }
        rule 364 {
            action accept
            destination {
                address 2001:470:99:5940:3a05:25ff:fe37:292a
                port 7175
            }
            protocol tcp_udp
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
            action drop
            description "Drop invalid state"
            state {
                invalid enable
            }
        }
        rule 21 {
            action accept
            description "Allow local"
            log disable
            protocol tcp_udp
            source {
                address 65.49.70.64/27
            }
        }
        rule 30 {
            action accept
            description "warp by-us-fmt-5-edge-5 enp33s0f1np1 http"
            destination {
                address 65.49.70.91
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 40 {
            action accept
            description "warp by-us-fmt-5-edge-5 enp33s0f1np1 https"
            destination {
                address 65.49.70.91
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 50 {
            action accept
            description "warp crisp eno2np1 http"
            destination {
                address 65.49.70.94
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 60 {
            action accept
            description "warp crisp eno2np1 https"
            destination {
                address 65.49.70.94
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 70 {
            action accept
            description "warp fireside eno2np1 http"
            destination {
                address 65.49.70.92
                port 80
            }
            log disable
            protocol tcp_udp
        }
        rule 80 {
            action accept
            description "warp fireside eno2np1 https"
            destination {
                address 65.49.70.92
                port 443
            }
            log disable
            protocol tcp_udp
        }
        rule 90 {
            action accept
            description "warp by-us-fmt-5-edge-5 enp33s0f1np1 https proxy"
            destination {
                address 65.49.70.91
                port 444
            }
            log disable
            protocol tcp_udp
        }
        rule 100 {
            action accept
            description "warp by-us-fmt-5-edge-5 enp33s0f1np1 socks"
            destination {
                address 65.49.70.91
                port 1080
            }
            log disable
            protocol tcp_udp
        }
        rule 110 {
            action accept
            description "warp fireside-eno2np1-proxy-g1-socks"
            destination {
                address 65.49.70.92
                port 7117
            }
            log disable
            protocol tcp_udp
        }
        rule 120 {
            action accept
            description "warp fireside-eno2np1-proxy-g1-http"
            destination {
                address 65.49.70.92
                port 7118
            }
            log disable
            protocol tcp_udp
        }
        rule 130 {
            action accept
            description "warp fireside-eno2np1-proxy-g1-https"
            destination {
                address 65.49.70.92
                port 7119
            }
            log disable
            protocol tcp_udp
        }
        rule 140 {
            action accept
            description "warp fireside-eno2np1-proxy-g1-api"
            destination {
                address 65.49.70.92
                port 7120
            }
            log disable
            protocol tcp_udp
        }
        rule 150 {
            action accept
            description "warp fireside-eno2np1-proxy-g1-wg"
            destination {
                address 65.49.70.92
                port 7121
            }
            log disable
            protocol tcp_udp
        }
        rule 160 {
            action accept
            description "warp fireside-eno2np1-proxy-g2-socks"
            destination {
                address 65.49.70.92
                port 7123
            }
            log disable
            protocol tcp_udp
        }
        rule 170 {
            action accept
            description "warp fireside-eno2np1-proxy-g2-http"
            destination {
                address 65.49.70.92
                port 7124
            }
            log disable
            protocol tcp_udp
        }
        rule 180 {
            action accept
            description "warp fireside-eno2np1-proxy-g2-https"
            destination {
                address 65.49.70.92
                port 7125
            }
            log disable
            protocol tcp_udp
        }
        rule 190 {
            action accept
            description "warp fireside-eno2np1-proxy-g2-api"
            destination {
                address 65.49.70.92
                port 7126
            }
            log disable
            protocol tcp_udp
        }
        rule 200 {
            action accept
            description "warp fireside-eno2np1-proxy-g2-wg"
            destination {
                address 65.49.70.92
                port 7127
            }
            log disable
            protocol tcp_udp
        }
        rule 210 {
            action accept
            description "warp fireside-eno2np1-proxy-g3-socks"
            destination {
                address 65.49.70.92
                port 7129
            }
            log disable
            protocol tcp_udp
        }
        rule 220 {
            action accept
            description "warp fireside-eno2np1-proxy-g3-http"
            destination {
                address 65.49.70.92
                port 7130
            }
            log disable
            protocol tcp_udp
        }
        rule 230 {
            action accept
            description "warp fireside-eno2np1-proxy-g3-https"
            destination {
                address 65.49.70.92
                port 7131
            }
            log disable
            protocol tcp_udp
        }
        rule 240 {
            action accept
            description "warp fireside-eno2np1-proxy-g3-api"
            destination {
                address 65.49.70.92
                port 7132
            }
            log disable
            protocol tcp_udp
        }
        rule 250 {
            action accept
            description "warp fireside-eno2np1-proxy-g3-wg"
            destination {
                address 65.49.70.92
                port 7133
            }
            log disable
            protocol tcp_udp
        }
        rule 260 {
            action accept
            description "warp fireside-eno2np1-proxy-g4-socks"
            destination {
                address 65.49.70.92
                port 7135
            }
            log disable
            protocol tcp_udp
        }
        rule 270 {
            action accept
            description "warp fireside-eno2np1-proxy-g4-http"
            destination {
                address 65.49.70.92
                port 7136
            }
            log disable
            protocol tcp_udp
        }
        rule 280 {
            action accept
            description "warp fireside-eno2np1-proxy-g4-https"
            destination {
                address 65.49.70.92
                port 7137
            }
            log disable
            protocol tcp_udp
        }
        rule 290 {
            action accept
            description "warp fireside-eno2np1-proxy-g4-api"
            destination {
                address 65.49.70.92
                port 7138
            }
            log disable
            protocol tcp_udp
        }
        rule 300 {
            action accept
            description "warp fireside-eno2np1-proxy-g4-wg"
            destination {
                address 65.49.70.92
                port 7139
            }
            log disable
            protocol tcp_udp
        }
        rule 310 {
            action accept
            description "warp fireside-eno2np1-proxy-g5-socks"
            destination {
                address 65.49.70.92
                port 7141
            }
            log disable
            protocol tcp_udp
        }
        rule 320 {
            action accept
            description "warp fireside-eno2np1-proxy-g5-http"
            destination {
                address 65.49.70.92
                port 7142
            }
            log disable
            protocol tcp_udp
        }
        rule 330 {
            action accept
            description "warp fireside-eno2np1-proxy-g5-https"
            destination {
                address 65.49.70.92
                port 7143
            }
            log disable
            protocol tcp_udp
        }
        rule 340 {
            action accept
            description "warp fireside-eno2np1-proxy-g5-api"
            destination {
                address 65.49.70.92
                port 7144
            }
            log disable
            protocol tcp_udp
        }
        rule 350 {
            action accept
            description "warp fireside-eno2np1-proxy-g5-wg"
            destination {
                address 65.49.70.92
                port 7145
            }
            log disable
            protocol tcp_udp
        }
        rule 360 {
            action accept
            description "warp fireside-eno2np1-proxy-g6-socks"
            destination {
                address 65.49.70.92
                port 7147
            }
            log disable
            protocol tcp_udp
        }
        rule 370 {
            action accept
            description "warp fireside-eno2np1-proxy-g6-http"
            destination {
                address 65.49.70.92
                port 7148
            }
            log disable
            protocol tcp_udp
        }
        rule 380 {
            action accept
            description "warp fireside-eno2np1-proxy-g6-https"
            destination {
                address 65.49.70.92
                port 7149
            }
            log disable
            protocol tcp_udp
        }
        rule 390 {
            action accept
            description "warp fireside-eno2np1-proxy-g6-api"
            destination {
                address 65.49.70.92
                port 7150
            }
            log disable
            protocol tcp_udp
        }
        rule 400 {
            action accept
            description "warp fireside-eno2np1-proxy-g6-wg"
            destination {
                address 65.49.70.92
                port 7151
            }
            log disable
            protocol tcp_udp
        }
        rule 410 {
            action accept
            description "warp fireside-eno2np1-proxy-g7-socks"
            destination {
                address 65.49.70.92
                port 7153
            }
            log disable
            protocol tcp_udp
        }
        rule 420 {
            action accept
            description "warp fireside-eno2np1-proxy-g7-http"
            destination {
                address 65.49.70.92
                port 7154
            }
            log disable
            protocol tcp_udp
        }
        rule 430 {
            action accept
            description "warp fireside-eno2np1-proxy-g7-https"
            destination {
                address 65.49.70.92
                port 7155
            }
            log disable
            protocol tcp_udp
        }
        rule 440 {
            action accept
            description "warp fireside-eno2np1-proxy-g7-api"
            destination {
                address 65.49.70.92
                port 7156
            }
            log disable
            protocol tcp_udp
        }
        rule 450 {
            action accept
            description "warp fireside-eno2np1-proxy-g7-wg"
            destination {
                address 65.49.70.92
                port 7157
            }
            log disable
            protocol tcp_udp
        }
        rule 460 {
            action accept
            description "warp fireside-eno2np1-proxy-g8-socks"
            destination {
                address 65.49.70.92
                port 7159
            }
            log disable
            protocol tcp_udp
        }
        rule 470 {
            action accept
            description "warp fireside-eno2np1-proxy-g8-http"
            destination {
                address 65.49.70.92
                port 7160
            }
            log disable
            protocol tcp_udp
        }
        rule 480 {
            action accept
            description "warp fireside-eno2np1-proxy-g8-https"
            destination {
                address 65.49.70.92
                port 7161
            }
            log disable
            protocol tcp_udp
        }
        rule 490 {
            action accept
            description "warp fireside-eno2np1-proxy-g8-api"
            destination {
                address 65.49.70.92
                port 7162
            }
            log disable
            protocol tcp_udp
        }
        rule 500 {
            action accept
            description "warp fireside-eno2np1-proxy-g8-wg"
            destination {
                address 65.49.70.92
                port 7163
            }
            log disable
            protocol tcp_udp
        }
        rule 510 {
            action accept
            description "warp fireside-eno2np1-proxy-g9-socks"
            destination {
                address 65.49.70.92
                port 7165
            }
            log disable
            protocol tcp_udp
        }
        rule 520 {
            action accept
            description "warp fireside-eno2np1-proxy-g9-http"
            destination {
                address 65.49.70.92
                port 7166
            }
            log disable
            protocol tcp_udp
        }
        rule 530 {
            action accept
            description "warp fireside-eno2np1-proxy-g9-https"
            destination {
                address 65.49.70.92
                port 7167
            }
            log disable
            protocol tcp_udp
        }
        rule 540 {
            action accept
            description "warp fireside-eno2np1-proxy-g9-api"
            destination {
                address 65.49.70.92
                port 7168
            }
            log disable
            protocol tcp_udp
        }
        rule 550 {
            action accept
            description "warp fireside-eno2np1-proxy-g9-wg"
            destination {
                address 65.49.70.92
                port 7169
            }
            log disable
            protocol tcp_udp
        }
        rule 560 {
            action accept
            description "warp fireside-eno2np1-proxy-g10-socks"
            destination {
                address 65.49.70.92
                port 7171
            }
            log disable
            protocol tcp_udp
        }
        rule 570 {
            action accept
            description "warp fireside-eno2np1-proxy-g10-http"
            destination {
                address 65.49.70.92
                port 7172
            }
            log disable
            protocol tcp_udp
        }
        rule 580 {
            action accept
            description "warp fireside-eno2np1-proxy-g10-https"
            destination {
                address 65.49.70.92
                port 7173
            }
            log disable
            protocol tcp_udp
        }
        rule 590 {
            action accept
            description "warp fireside-eno2np1-proxy-g10-api"
            destination {
                address 65.49.70.92
                port 7174
            }
            log disable
            protocol tcp_udp
        }
        rule 600 {
            action accept
            description "warp fireside-eno2np1-proxy-g10-wg"
            destination {
                address 65.49.70.92
                port 7175
            }
            log disable
            protocol tcp_udp
        }
        rule 710 {
            action accept
            description "warp crisp-eno2np1-proxy-g1-socks"
            destination {
                address 65.49.70.94
                port 7117
            }
            log disable
            protocol tcp_udp
        }
        rule 720 {
            action accept
            description "warp crisp-eno2np1-proxy-g1-http"
            destination {
                address 65.49.70.94
                port 7118
            }
            log disable
            protocol tcp_udp
        }
        rule 730 {
            action accept
            description "warp crisp-eno2np1-proxy-g1-https"
            destination {
                address 65.49.70.94
                port 7119
            }
            log disable
            protocol tcp_udp
        }
        rule 740 {
            action accept
            description "warp crisp-eno2np1-proxy-g1-api"
            destination {
                address 65.49.70.94
                port 7120
            }
            log disable
            protocol tcp_udp
        }
        rule 750 {
            action accept
            description "warp crisp-eno2np1-proxy-g1-wg"
            destination {
                address 65.49.70.94
                port 7121
            }
            log disable
            protocol tcp_udp
        }
        rule 760 {
            action accept
            description "warp crisp-eno2np1-proxy-g2-socks"
            destination {
                address 65.49.70.94
                port 7123
            }
            log disable
            protocol tcp_udp
        }
        rule 770 {
            action accept
            description "warp crisp-eno2np1-proxy-g2-http"
            destination {
                address 65.49.70.94
                port 7124
            }
            log disable
            protocol tcp_udp
        }
        rule 780 {
            action accept
            description "warp crisp-eno2np1-proxy-g2-https"
            destination {
                address 65.49.70.94
                port 7125
            }
            log disable
            protocol tcp_udp
        }
        rule 790 {
            action accept
            description "warp crisp-eno2np1-proxy-g2-api"
            destination {
                address 65.49.70.94
                port 7126
            }
            log disable
            protocol tcp_udp
        }
        rule 800 {
            action accept
            description "warp crisp-eno2np1-proxy-g2-wg"
            destination {
                address 65.49.70.94
                port 7127
            }
            log disable
            protocol tcp_udp
        }
        rule 810 {
            action accept
            description "warp crisp-eno2np1-proxy-g3-socks"
            destination {
                address 65.49.70.94
                port 7129
            }
            log disable
            protocol tcp_udp
        }
        rule 820 {
            action accept
            description "warp crisp-eno2np1-proxy-g3-http"
            destination {
                address 65.49.70.94
                port 7130
            }
            log disable
            protocol tcp_udp
        }
        rule 830 {
            action accept
            description "warp crisp-eno2np1-proxy-g3-https"
            destination {
                address 65.49.70.94
                port 7131
            }
            log disable
            protocol tcp_udp
        }
        rule 840 {
            action accept
            description "warp crisp-eno2np1-proxy-g3-api"
            destination {
                address 65.49.70.94
                port 7132
            }
            log disable
            protocol tcp_udp
        }
        rule 850 {
            action accept
            description "warp crisp-eno2np1-proxy-g3-wg"
            destination {
                address 65.49.70.94
                port 7133
            }
            log disable
            protocol tcp_udp
        }
        rule 860 {
            action accept
            description "warp crisp-eno2np1-proxy-g4-socks"
            destination {
                address 65.49.70.94
                port 7135
            }
            log disable
            protocol tcp_udp
        }
        rule 870 {
            action accept
            description "warp crisp-eno2np1-proxy-g4-http"
            destination {
                address 65.49.70.94
                port 7136
            }
            log disable
            protocol tcp_udp
        }
        rule 880 {
            action accept
            description "warp crisp-eno2np1-proxy-g4-https"
            destination {
                address 65.49.70.94
                port 7137
            }
            log disable
            protocol tcp_udp
        }
        rule 890 {
            action accept
            description "warp crisp-eno2np1-proxy-g4-api"
            destination {
                address 65.49.70.94
                port 7138
            }
            log disable
            protocol tcp_udp
        }
        rule 900 {
            action accept
            description "warp crisp-eno2np1-proxy-g4-wg"
            destination {
                address 65.49.70.94
                port 7139
            }
            log disable
            protocol tcp_udp
        }
        rule 910 {
            action accept
            description "warp crisp-eno2np1-proxy-g5-socks"
            destination {
                address 65.49.70.94
                port 7141
            }
            log disable
            protocol tcp_udp
        }
        rule 920 {
            action accept
            description "warp crisp-eno2np1-proxy-g5-http"
            destination {
                address 65.49.70.94
                port 7142
            }
            log disable
            protocol tcp_udp
        }
        rule 930 {
            action accept
            description "warp crisp-eno2np1-proxy-g5-https"
            destination {
                address 65.49.70.94
                port 7143
            }
            log disable
            protocol tcp_udp
        }
        rule 940 {
            action accept
            description "warp crisp-eno2np1-proxy-g5-api"
            destination {
                address 65.49.70.94
                port 7144
            }
            log disable
            protocol tcp_udp
        }
        rule 950 {
            action accept
            description "warp crisp-eno2np1-proxy-g5-wg"
            destination {
                address 65.49.70.94
                port 7145
            }
            log disable
            protocol tcp_udp
        }
        rule 960 {
            action accept
            description "warp crisp-eno2np1-proxy-g6-socks"
            destination {
                address 65.49.70.94
                port 7147
            }
            log disable
            protocol tcp_udp
        }
        rule 970 {
            action accept
            description "warp crisp-eno2np1-proxy-g6-http"
            destination {
                address 65.49.70.94
                port 7148
            }
            log disable
            protocol tcp_udp
        }
        rule 980 {
            action accept
            description "warp crisp-eno2np1-proxy-g6-https"
            destination {
                address 65.49.70.94
                port 7149
            }
            log disable
            protocol tcp_udp
        }
        rule 990 {
            action accept
            description "warp crisp-eno2np1-proxy-g6-api"
            destination {
                address 65.49.70.94
                port 7150
            }
            log disable
            protocol tcp_udp
        }
        rule 1000 {
            action accept
            description "warp crisp-eno2np1-proxy-g6-wg"
            destination {
                address 65.49.70.94
                port 7151
            }
            log disable
            protocol tcp_udp
        }
        rule 1010 {
            action accept
            description "warp crisp-eno2np1-proxy-g7-socks"
            destination {
                address 65.49.70.94
                port 7153
            }
            log disable
            protocol tcp_udp
        }
        rule 1020 {
            action accept
            description "warp crisp-eno2np1-proxy-g7-http"
            destination {
                address 65.49.70.94
                port 7154
            }
            log disable
            protocol tcp_udp
        }
        rule 1030 {
            action accept
            description "warp crisp-eno2np1-proxy-g7-https"
            destination {
                address 65.49.70.94
                port 7155
            }
            log disable
            protocol tcp_udp
        }
        rule 1040 {
            action accept
            description "warp crisp-eno2np1-proxy-g7-api"
            destination {
                address 65.49.70.94
                port 7156
            }
            log disable
            protocol tcp_udp
        }
        rule 1050 {
            action accept
            description "warp crisp-eno2np1-proxy-g7-wg"
            destination {
                address 65.49.70.94
                port 7157
            }
            log disable
            protocol tcp_udp
        }
        rule 1060 {
            action accept
            description "warp crisp-eno2np1-proxy-g8-socks"
            destination {
                address 65.49.70.94
                port 7159
            }
            log disable
            protocol tcp_udp
        }
        rule 1070 {
            action accept
            description "warp crisp-eno2np1-proxy-g8-http"
            destination {
                address 65.49.70.94
                port 7160
            }
            log disable
            protocol tcp_udp
        }
        rule 1080 {
            action accept
            description "warp crisp-eno2np1-proxy-g8-https"
            destination {
                address 65.49.70.94
                port 7161
            }
            log disable
            protocol tcp_udp
        }
        rule 1090 {
            action accept
            description "warp crisp-eno2np1-proxy-g8-api"
            destination {
                address 65.49.70.94
                port 7162
            }
            log disable
            protocol tcp_udp
        }
        rule 1100 {
            action accept
            description "warp crisp-eno2np1-proxy-g8-wg"
            destination {
                address 65.49.70.94
                port 7163
            }
            log disable
            protocol tcp_udp
        }
        rule 1110 {
            action accept
            description "warp crisp-eno2np1-proxy-g9-socks"
            destination {
                address 65.49.70.94
                port 7165
            }
            log disable
            protocol tcp_udp
        }
        rule 1120 {
            action accept
            description "warp crisp-eno2np1-proxy-g9-http"
            destination {
                address 65.49.70.94
                port 7166
            }
            log disable
            protocol tcp_udp
        }
        rule 1130 {
            action accept
            description "warp crisp-eno2np1-proxy-g9-https"
            destination {
                address 65.49.70.94
                port 7167
            }
            log disable
            protocol tcp_udp
        }
        rule 1140 {
            action accept
            description "warp crisp-eno2np1-proxy-g9-api"
            destination {
                address 65.49.70.94
                port 7168
            }
            log disable
            protocol tcp_udp
        }
        rule 1150 {
            action accept
            description "warp crisp-eno2np1-proxy-g9-wg"
            destination {
                address 65.49.70.94
                port 7169
            }
            log disable
            protocol tcp_udp
        }
        rule 1160 {
            action accept
            description "warp crisp-eno2np1-proxy-g10-socks"
            destination {
                address 65.49.70.94
                port 7171
            }
            log disable
            protocol tcp_udp
        }
        rule 1170 {
            action accept
            description "warp crisp-eno2np1-proxy-g10-http"
            destination {
                address 65.49.70.94
                port 7172
            }
            log disable
            protocol tcp_udp
        }
        rule 1180 {
            action accept
            description "warp crisp-eno2np1-proxy-g10-https"
            destination {
                address 65.49.70.94
                port 7173
            }
            log disable
            protocol tcp_udp
        }
        rule 1190 {
            action accept
            description "warp crisp-eno2np1-proxy-g10-api"
            destination {
                address 65.49.70.94
                port 7174
            }
            log disable
            protocol tcp_udp
        }
        rule 1200 {
            action accept
            description "warp crisp-eno2np1-proxy-g10-wg"
            destination {
                address 65.49.70.94
                port 7175
            }
            log disable
            protocol tcp_udp
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
    }
    receive-redirects disable
    send-redirects enable
    source-validation disable
    syn-cookies enable
}
interfaces {
    bridge br0 {
        address 192.168.72.1/24
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
        address 65.49.70.89/27
        address 2001:470:99::59/48
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
        address 2001:470:99:5930::1/64
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
                prefix 2001:470:99:5930::/64 {
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
        address 2001:470:99:5940::1/64
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
                prefix 2001:470:99:5940::/64 {
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
        address 2001:470:99:5950::1/64
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
                prefix 2001:470:99:5950::/64 {
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
        address 2001:470:99:5960::1/64
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
                prefix 2001:470:99:5960::1/64 {
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
        duplex auto
        speed auto
    }
    ethernet eth8 {
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
        interface-route 65.49.70.91/32 {
            next-hop-interface eth3 {
            }
        }
        interface-route 65.49.70.92/32 {
            next-hop-interface eth6 {
            }
        }
        interface-route 65.49.70.94/32 {
            next-hop-interface eth4 {
            }
        }
        route6 ::/0 {
            next-hop 2001:470:99::1 {
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
            subnet 192.168.72.0/24 {
                default-router 192.168.72.1
                dns-server 192.168.72.1
                lease 86400
                start 192.168.72.38 {
                    stop 192.168.72.243
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
    }
    ssh {
        port 22
        protocol-version v2
    }
    unms {
        connection wss://bringyour.uisp.com:443+SCRUBBEDUISPKEYSCRUBBEDUISPKEYSCRUBBEDUISPKEYAAAA+allowUntrustedCertificate
    }
}
system {
    analytics-handler {
        send-analytics-report true
    }
    crash-handler {
        send-crash-report true
    }
    gateway-address 65.49.70.65
    host-name by-us-fmt-5-9
    login {
        user ubnt {
            authentication {
                encrypted-password $5$SCRUBBEDSALT$SCRUBBEDHASHSCRUBBEDHASHSCRUBBEDHASHSCRUBBE
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
