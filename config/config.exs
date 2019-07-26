use Mix.Config

config :emqx,
  expand_plugins_dir: 'plugins/',
  plugins_etc_dir: 'etc/plugins/'

config :kvs,
  dba: :kvs_mnesia,
  dba_st: :kvs_stream,
  schema: [:kvs, :kvs_stream]
