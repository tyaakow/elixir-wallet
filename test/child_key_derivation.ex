defmodule ChildKeyDerivation do
  use ExUnit.Case


  test "derive child extended key" do

    seed_hex = "000102030405060708090a0b0c0d0e0f"
    seed_bin = seed_hex |> Base.decode16!(case: :mixed)
    master_priv_key = KeyPair.generate_master_private_key(seed_bin)
    master_chain_code = KeyPair.generate_chain_code(seed_bin)

    IO.inspect "Master Private Key"
    IO.inspect master_priv_key
    IO.inspect "Master Chain Code"
    IO.inspect master_chain_code

    {extended_bin, extended_base58} =
      KeyPair.derive_extend_priv_key(0, <<0::32>>, 0, master_priv_key, master_chain_code)

    assert "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    = extended_base58


    ###################### CHILD PRIVATE KEY ##################################
    index = 2147483648

    {child_key, child_chain_code} =
      KeyPair.child_private_key_derivation(master_priv_key, master_chain_code, index)

    IO.inspect "Child key"
    IO.inspect :binary.encode_unsigned(child_key)

    IO.inspect "Child chain code"
    IO.inspect child_chain_code

    f_print = master_priv_key |> KeyPair.generate_master_public_key() |> KeyPair.serialize() |> Base.decode16!() |> KeyPair.fingerprint()

    IO.inspect "Fingerprint"
    IO.inspect f_print

    {child_bin, child_base58} =
      KeyPair.derive_extend_priv_key(1, f_print, index, child_key, child_chain_code)

    assert "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    = child_base58

    ###################### CHILD PRIVATE KEY ##################################

    master_pub_key = KeyPair.generate_master_public_key(master_priv_key)

    {extended_bin, extended_base58} =
      KeyPair.derive_extend_pub_key(0, <<0::32>>, 0, master_pub_key |> KeyPair.serialize() |> Base.decode16!(), master_chain_code)

    assert "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    = extended_base58


    ##{pub_key, child_chain_code} = KeyPair.child_public_key_derivation(master_pub_key, master_chain_code, index)

    pub = KeyPair.generate_master_public_key(child_key) |> KeyPair.serialize() |> Base.decode16!()


    {child_bin, child_base58} =
      KeyPair.derive_extend_pub_key(1, f_print, index, pub, child_chain_code)

    assert "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    = child_base58



    ##{child_bin, child_base58} =
    #  KeyPair.derive_extend_priv_key(1, f_print, 0, child_key, child_chain_code)
  end

  test "derive_path" do
    #IO.inspect "############################# DERIVE PATH #############################"
    #IO.inspect(derive_path("m/0'"))
    #IO.inspect "############################# DERIVE PATH #############################"
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
