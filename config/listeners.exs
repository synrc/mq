import Config

config :emqx,
    listeners: [
    {:tcp, {'0.0.0.0',11883},[
        {:tcp_options, [
            {:backlog,512},
            {:send_timeout,5000},
            {:send_timeout_close,true},
            {:nodelay,false},
            {:reuseaddr,true}
        ]},
        {:acceptors,4},
        {:max_connections,1024000},
        {:max_conn_rate,1000},
        {:active_n,1000},
        {:zone,:internal}
    ]},
    {:tcp, {'0.0.0.0',1883},[
        {:tcp_options, [{:backlog,1024},{:send_timeout,15000},{:send_timeout_close,true},{:nodelay,true},{:reuseaddr,true}]},
        {:acceptors,8},
        {:max_connections,1024000},
        {:max_conn_rate,1000},
        {:active_n,100},
        {:zone,:external},
        {:access_rules,[{:allow,:all}]}
    ]},
    {:ws, 8083, [
        {:tcp_options, [{:backlog,1024},{:send_timeout,15000},{:send_timeout_close,true},{:nodelay,true}]},
        {:acceptors,4},
        {:mqtt_path,'/mqtt'},
        {:max_connections,102400},
        {:max_conn_rate,1000},
        {:zone,:external},
        {:verify_protocol_header,true},
        {:access_rules,[{:allow,:all}]}
    ]},
    {:ssl,8883, [
        {:tcp_options, [{:backlog,1024},{:send_timeout,15000},{:send_timeout_close,true},{:nodelay,true},{:reuseaddr,true}]},
        {:ssl_options,[
            {:ciphers, [
                'ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES256-SHA384','ECDHE-RSA-AES256-SHA384',
                'ECDHE-ECDSA-DES-CBC3-SHA','ECDH-ECDSA-AES256-GCM-SHA384',
                'ECDH-RSA-AES256-GCM-SHA384','ECDH-ECDSA-AES256-SHA384',
                'ECDH-RSA-AES256-SHA384','DHE-DSS-AES256-GCM-SHA384',
                'DHE-DSS-AES256-SHA256','AES256-GCM-SHA384','AES256-SHA256',
                'ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES128-SHA256','ECDHE-RSA-AES128-SHA256',
                'ECDH-ECDSA-AES128-GCM-SHA256','ECDH-RSA-AES128-GCM-SHA256',
                'ECDH-ECDSA-AES128-SHA256','ECDH-RSA-AES128-SHA256',
                'DHE-DSS-AES128-GCM-SHA256','DHE-DSS-AES128-SHA256',
                'AES128-GCM-SHA256','AES128-SHA256','ECDHE-ECDSA-AES256-SHA',
                'ECDHE-RSA-AES256-SHA','DHE-DSS-AES256-SHA',
                'ECDH-ECDSA-AES256-SHA','ECDH-RSA-AES256-SHA','AES256-SHA',
                'ECDHE-ECDSA-AES128-SHA','ECDHE-RSA-AES128-SHA',
                'DHE-DSS-AES128-SHA','ECDH-ECDSA-AES128-SHA','ECDH-RSA-AES128-SHA',
                'AES128-SHA'
            ]},
            {:handshake_timeout,15000},
            {:keyfile,'etc/certs/key.pem'},
            {:certfile,'etc/certs/cert.pem'},
            {:reuse_sessions,true},
            {:acceptors,16},
            {:max_connections,102400},
            {:max_conn_rate,500},
            {:active_n,100},
            {:zone,:external},
            {:access_rules,[{:allow,:all}]}
        ]}
    ]},
    {:wss,8084, [
        {:tcp_options, [{:backlog,1024},{:send_timeout,15000},{:send_timeout_close,true},{:nodelay,true}]},
        {:ssl_options, [
            {:ciphers, [
                'ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-AES256-SHA384','ECDHE-RSA-AES256-SHA384',
                'ECDHE-ECDSA-DES-CBC3-SHA','ECDH-ECDSA-AES256-GCM-SHA384',
                'ECDH-RSA-AES256-GCM-SHA384','ECDH-ECDSA-AES256-SHA384',
                'ECDH-RSA-AES256-SHA384','DHE-DSS-AES256-GCM-SHA384',
                'DHE-DSS-AES256-SHA256','AES256-GCM-SHA384','AES256-SHA256',
                'ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES128-SHA256','ECDHE-RSA-AES128-SHA256',
                'ECDH-ECDSA-AES128-GCM-SHA256','ECDH-RSA-AES128-GCM-SHA256',
                'ECDH-ECDSA-AES128-SHA256','ECDH-RSA-AES128-SHA256',
                'DHE-DSS-AES128-GCM-SHA256','DHE-DSS-AES128-SHA256',
                'AES128-GCM-SHA256','AES128-SHA256','ECDHE-ECDSA-AES256-SHA',
                'ECDHE-RSA-AES256-SHA','DHE-DSS-AES256-SHA',
                'ECDH-ECDSA-AES256-SHA','ECDH-RSA-AES256-SHA','AES256-SHA',
                'ECDHE-ECDSA-AES128-SHA','ECDHE-RSA-AES128-SHA',
                'DHE-DSS-AES128-SHA','ECDH-ECDSA-AES128-SHA','ECDH-RSA-AES128-SHA',
                'AES128-SHA'
            ]},
            {:keyfile,'etc/certs/key.pem'},
            {:certfile,'etc/certs/cert.pem'},
            {:reuse_sessions,true}
        ]},
        {:acceptors,4},
        {:mqtt_path,'/mqtt'},
        {:max_connections,16},
        {:max_conn_rate,1000},
        {:zone,:external},
        {:verify_protocol_header,true},
        {:access_rules,[{:allow,:all}]}
    ]} 
    ]
