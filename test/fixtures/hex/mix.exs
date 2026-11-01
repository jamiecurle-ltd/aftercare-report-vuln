# A scratch project for the CI tests: it locks a retired Hex package
# (hackney 1.6.4) and a vulnerable one (ssl_verify_fun 1.1.7), so the action
# has something to find. Never compiled; `mix deps.get` only fetches.
defmodule Fixture.MixProject do
  use Mix.Project

  def project, do: [app: :fixture, version: "0.1.0", deps: [{:ssl_verify_fun, "== 1.1.7"}, {:hackney, "== 1.6.4"}]]
end
