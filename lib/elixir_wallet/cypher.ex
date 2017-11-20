defmodule Cypher do
  @moduledoc """
  Module for encrypting and decrypting the mnemonic phrase
  using AES-256 with CBC encryption mode
  """

  @doc """
  Encrypts a given text with the given password
  ## Example
      iex> Cypher.encrypt("text to encrypt", "password")
      <<136, 7, 40, 34, 243, 197, 46, 85, 173, 122, 0, 176, 1, 60, 15, 99, 19, 160,
      17, 210, 250, 4, 63, 28, 12, 56, 130, 141, 141, 230, 48>>
  """
  @spec encrypt(String.t(), String.t()) :: BitString.t()
  def encrypt(text_to_encrypt, password) do
    {ivec, init} = get_stream_state(password)
    {_, encrypted_data} = :crypto.stream_encrypt(init, text_to_encrypt)
    ivec <> encrypted_data
  end

  @doc """
  Decrypts the given encrypted data with the given password
  ## Example
      encrypted = <<136, 7, 40, 34, 243, 197, 46, 85, 173, 122, 0, 176, 1, 60, 15,
      99, 19, 160, 17, 210, 250, 4, 63, 28, 12, 56, 130, 141, 141, 230, 48>>
      iex> Cypher.decrypt(encrypted_text, "password")
      "text to encrypt"
  """
  def decrypt(<<ivec::binary-16, encrypted_text::binary>>, password) do
    init = get_stream_state(password, ivec)
    {_, decrypted_text} = :crypto.stream_decrypt(init, encrypted_text)
    decrypted_text
  end

  defp get_stream_state(password) do
    {password_dec, _} = Integer.parse(password |> Base.encode16(), 16)
    key = <<password_dec::size(256)>>
    ivec = :crypto.strong_rand_bytes(16)
    {ivec, :crypto.stream_init(:aes_ctr, key, ivec)}
  end
  defp get_stream_state(password, ivec) do
    {password_dec, _} = Integer.parse(password |> Base.encode16(), 16)
    key = <<password_dec::size(256)>>
    :crypto.stream_init(:aes_ctr, key, ivec)
  end
end
