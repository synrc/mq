use Mix.Config

config :emqx,
  expand_plugins_dir: 'plugins/',
  plugins_etc_dir: 'etc/plugins/'

config :emqx_dashboard,
  default_user_passwd: 'public',
  default_user_username: 'admin',
  api_providers: [ :emqx_management, :emqx_dashboard ],
  listeners: [ {:http,18083, [ {:num_acceptors,4},
                               {:max_connections,512}]}]

config :emqx_management,
  max_row_limit: 10000,
  listeners: [ {:http,8080, [ {:backlog,512},
                              {:send_timeout,15000},
                              {:send_timeout_close,true},
                              {:nodelay,true},
                              {:num_acceptors,2},
                              {:max_connections,64000}]}]

config :kvs,
  dba: :kvs_mnesia,
  dba_st: :kvs_stream,
  schema: [:kvs, :kvs_stream]
