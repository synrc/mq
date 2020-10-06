defmodule XIO.Mixfile do
  use Mix.Project

  def project() do
    [
      app: :xio,
      version: "0.7.0",
      elixir: "~> 1.7",
      description: "XIO EMQ X 3.0 Elixir",
      package: package(),
      deps: deps()
    ]
  end

  def package do
    [
      files: ~w(doc include lib src mix.exs LICENSE),
      licenses: ["ISC"],
      maintainers: ["Namdak Tonpa"],
      name: :xio,
      links: %{"GitHub" => "https://github.com/enterprizing/xio"}
    ]
  end

  def application() do
    [
      mod: {:xio, []},
      extra_applications: [:os_mon], # for mix release
      application: [
        :inets,
        :mnesia,
        :cuttlefish,
        :getopt,
        :gproc,
        :neotoma,
        :replayq,
        :clique,
        :asn1,
        :compiler,
        :syntax_tools,
        :jsx,
        :crypto,
        :cowlib,
        :ekka,
        :goldrush,
        :public_key,
        :lager,
        :ssl,
        :ranch,
        :esockd,
        :gen_rpc,
        :ssl_verify_fun,
        :cowboy,
        :emqx,
        :os_mon,
        :minirest,
        :emqx_management,
        :emqx_dashboard
      ]
    ]
  end

  def deps() do
    [
      {:kvs, "~> 7.9.1", override: true},
      {:rocksdb, github: "enterprizing/rocksdb"},
      {:minirest, github: "xio/minirest", ref: "emqx42", override: true},
      {:cuttlefish, github: "xio/cuttlefish", branch: "develop", override: true},
      {:clique, github: "xio/clique", branch: "master", override: true},
      {:emqx, github: "xio/emqx", ref: "v4.2", override: true},
      {:emqx_dashboard,  github: "xio/emqx-dashboard", ref: "v4.2", override: true},
      {:emqx_management, github: "xio/emqx-management", ref: "v4.2", override: true},
      {:gproc, "~> 0.8.0", override: true},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
