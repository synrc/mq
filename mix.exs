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
        :gproc,
        :neotoma,
        :replayq,
        :clique,
        :asn1,
        :compiler,
        :syntax_tools,
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
        :emqx_dashboard
      ]
    ]
  end

  def deps() do
    [
      {:kvs, "~> 7.11.5", override: true},
      {:ranch, "~> 1.7.1", override: true},
      {:cowboy, "~> 2.8.0", override: true},
      {:cowlib, "~> 2.9.0", override: true},
      {:emqx, github: "xio/emqx", ref: "master"},
      {:emqx_dashboard, github: "xio/emqx-dashboard", ref: "erp.uno"},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end
end
