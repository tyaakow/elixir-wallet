defmodule WalletCrypto do
  @moduledoc """
  Module for encrypting and decrypting wallet files
  """
  alias Cryptex.KeyGenerator
  alias Cryptex.MessageEncryptor

  def decrypt_wallet(filename, password, phrase) do
    {:ok, data} = File.read(filename)
    encryptor = generate_encryptor(password,phrase)
    MessageEncryptor.decrypt_and_verify(encryptor, data)
  end

  def encrypt_wallet(data,password, phrase) do
    encryptor = generate_encryptor(password, phrase)
    MessageEncryptor.encrypt_and_sign(encryptor, data)
  end

  def generate_encryptor(password, phrase) do
    secret_key_base = :crypto.hash(:sha256, password) |> Base.encode16()
    encrypted_salt = :crypto.hash(:sha256, phrase) |> Base.encode16()
    secret = KeyGenerator.generate(secret_key_base, phrase)
    sign_secret = KeyGenerator.generate(secret_key_base, encrypted_salt)
    MessageEncryptor.new(secret, sign_secret)
  end

end
