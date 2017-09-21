defmodule Mnemonic do

  alias GenerateIndexes

  def get_wordlist() do
    {:ok,words} = File.read "priv/wordlist.txt"
    String.replace(words, "\n", ",")
    |>String.split(",")
    |>List.to_tuple
  end

  def generate_phrase(indexes) do
    phrase = ""
    phrase = for n <- indexes do
      phrase <> elem(get_wordlist(),n) <> " "
    end
    phrase |> List.to_string |> String.trim
  end

  def generate_root_seed(mnemonic, password, opts \\ []) do
    KeyGenerator.generate(mnemonic, password, opts)
    |> generate_master_keys
  end

  def generate_master_keys(seed) do
    seed_binary = seed |> Bits.extract |> Enum.join
    <<private::size(256),chain_code::binary>> = seed
    private_hex = <<private::256>> |> Base.encode16
    {public,private} = :crypto.generate_key(:ecdh,:secp256k1,private_hex)
    {private,public,chain_code}
  end

end
