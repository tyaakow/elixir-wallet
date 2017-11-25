defmodule Signing do

  @moduledoc """
  Module for signing and verifying transactions using the ECDSA algorithm
  """

  @doc """
   Signs a transaction using a private key
  ## Examples
      iex> Signing.sign(<<0,1>>, <<100, 208, 92, 132, 43, 104, 6, 55, 125, 18, 18, 215, 98, 8, 245, 12, 78, 92,
      89, 115, 59, 231, 28, 142, 137, 119, 62, 19, 102, 238, 171, 185>>)
      <<48, 70, 2, 33, 0, 228, 179, 41, 106, 184, 31, 168, 184, 227, 240, 145, 166,
      93, 47, 64, 11, 104, 94, 240, 192, 240, 229, 55, 137, 226, 15, 119, 156, 52,
      165, 170, 163, 2, 33, 0, 234, 132, 82, 122, 244, 209, 148, 232, 124, 216, ...>>
  """
  @spec sign(Binary.t(), Binary.t()) :: Binary.t()
  def sign(message, privkey_bin) do
    :crypto.sign(:ecdsa, :sha256, message, [privkey_bin, :secp256k1])
  end

  @doc """
   Verifies a signed transaction using a public key 
  ## Examples
      iex> Signing.verify
      (<<0,1>>, 
      <<48, 70, 2, 33, 0, 228, 179, 41, 106, 184, 31, 168, 184, 227, 240, 145, 166,
      93, 47, 64, 11, 104, 94, 240, 192, 240, 229, 55, 137, 226, 15, 119, 156, 52,
      165, 170, 163, 2, 33, 0, 234, 132, 82, 122, 244, 209, 148, 232, 124, 216, ...>>, 
      <<4, 210, 200, 166, 81, 219, 54, 116, 39, 64, 199, 57, 55, 152, 204, 119, 237,
      168, 175, 243, 132, 39, 71, 208, 94, 138, 190, 242, 78, 74, 141, 43, 58, 241,
      15, 19, 179, 45, 42, 79, 118, 24, 160, 20, 64, 178, 109, 124, 172, 127, ...>>)
      
      :true
  """
  @spec verify(Binary.t(), Binary.t(), Binary.t()) :: Atom.t()
  def verify(message, signature_bin, pubkey_bin) do
    if (:crypto.verify(:ecdsa, :sha256, message, signature_bin, [pubkey_bin, :secp256k1])) do
      :true
    else
      :false
    end 
  end
end
