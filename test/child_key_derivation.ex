defmodule ChildKeyDerivation do
  use ExUnit.Case


  test "derive child extended key" do

    seed_hex = "000102030405060708090a0b0c0d0e0f"
    seed_bin = seed_hex |> Base.decode16!(case: :mixed)
    master_priv_key = KeyPair.generate_master_private_key(seed_bin)
    master_chain_code = KeyPair.generate_chain_code(seed_bin)

    {extended_bin, extended_base58} =
      KeyPair.derive_extend_priv_key(0, 0, 0, master_priv_key, master_chain_code)

    assert "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    = extended_base58

    index = 2147483648

    {child_key, child_chain_code} =
      KeyPair.child_private_key_derivation(master_priv_key, master_chain_code, index)
    IO.inspect "Child key: #{child_key}"
    IO.inspect "Child chain code: #{child_chain_code}"

    f_print = master_priv_key |> KeyPair.generate_master_public_key() |> KeyPair.fingerprint()
    IO.inspect f_print

    {child_bin, child_base58} =
      KeyPair.derive_extend_priv_key(1, f_print, index, child_key, child_chain_code)

    assert "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    = child_base58

  end

  test "derive_path" do
    IO.inspect "############################# DERIVE PATH #############################"
    IO.inspect(derive_path("m/0'/5/1/5"))
    IO.inspect "############################# DERIVE PATH #############################"
  end


  def derive_path(<<"m/", path::binary>>) do
    :lists.map(fn(e) ->
      case String.reverse(e) do
        <<"'", hardened::binary>> ->
          {num, _rest} = Integer.parse(String.reverse(hardened))
          final = num + 2147483648
          final
        _ ->
          {num, _rest} = Integer.parse(e)
          num
      end
    end, :binary.split(path, <<"/">>, [:global]))
  end

end
