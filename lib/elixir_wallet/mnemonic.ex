defmodule Mnemonic do

  alias GenerateIndexes

  def get_wordlist() do
    {:ok, words} = File.read "priv/wordlist.txt"
    String.replace(words, "\n", ",") |> String.split(",") |> List.to_tuple()
  end

  def generate_phrase(indexes) do
    phrase = ""
    phrase = for n <- indexes do
      phrase <> elem(get_wordlist(),n) <> " "
    end
    phrase |> List.to_string() |> String.trim()
  end

  def generate_root_seed(mnemonic, password, opts \\ []) do
    generate_master_keys(KeyGenerator.generate(mnemonic, password, opts))
  end

  def generate_master_keys(seed) do
    <<private::size(256), chain_code::binary>> = seed
    private_hex = <<private::256>> |> Base.encode16()
    {public, _} = :crypto.generate_key(:ecdh, :secp256k1, private)
    second_half = public|>Base.encode16 |> String.slice(2, 128) |> String.slice(64, 64)
    first_half = public|>Base.encode16 |> String.slice(2, 128) |> String.slice(0, 64)
    {last_digit_int, _} = second_half |> String.slice(63, 63)|>Integer.parse(16)
    public_short = cond do
      rem(last_digit_int,2) == 0 ->
        "02" <> first_half
      rem(last_digit_int,2) != 0 ->
        "03" <> first_half
    end
    {private_hex, public_short, chain_code}
   end

end
