defmodule ElixirWallet.Mixfile do
  use Mix.Project

  def project do
    [
      app: :elixir_wallet,
      version: "0.1.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:cryptex, "~> 0.0.1"},
      {:base58, github: "titan098/erl-base58"},
      {:key_generator, github: "scrogson/key_generator"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
    ]
  end
end
