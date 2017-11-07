defmodule ElixirWalletTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "greets the world" do
    assert ElixirWallet.hello() == :world
  end
end
