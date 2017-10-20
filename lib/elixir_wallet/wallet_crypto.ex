defmodule WalletCrypto do
  @moduledoc """
  Module for encrypting and decrypting wallet files
  """
  alias Cryptex.KeyGenerator
  alias Cryptex.MessageEncryptor

  @doc """
  Decripts the data of the wallet file
  using the password and mnemonic_phrase as encriptors
  ## Example
      iex> WalletCrypto.decrypt_wallet("file_path", "pass", "mnemonic_phrase")
      %{address: "17sK9AinWc531hbd2NvY87HYGjLhov8W",1a065dabd5ab0da67a439cb99beaf6284a0cf9f8
        private_key: "6F1F227BF23C7EAB583279B299330B0535B68AE98A2ADD1BF0CB2C1E7E0E0EB6"
        public: "02EEF538AEDB61AAB3276639AEA01EF24A7AC1E467DA2BA57619DEE987F2626E68"}
  """
  @spec decrypt_wallet(String.t(), String.t(), String.t()) :: Map.t()
  def decrypt_wallet(file_path, password, mnemonic_phrase) do
    case File.read(file_path) do
      {:ok, encrypted_data} ->
        encryptor = generate_encryptor(password, mnemonic_phrase)
        {:ok, MessageEncryptor.decrypt_and_verify(encryptor, encrypted_data)}
      {:error, :enoent} ->
        {:error, "The file does not exist."}
      {:error, :eaccess} ->
        {:error, "Missing permision for reading the file,
        or for searching one of the parent directories."}
      {:error, :eisdir} ->
        {:error, "The named file is a directory."}
      {:error, :enotdir} ->
        {:error, "A component of the file name is not a directory."}
      {:error, :enomem} ->
        {:error, "There is not enough memory for the contents of the file."}
    end
  end

  @doc """
  Encripts the data of the wallet file
  using the password and mnemonic_phrase as encriptors
  ## Example
      iex> Wallet.encrypt_wallet("data_to_encript", "pass", "mnemonic_phrase")
      "dhawduHAWdgmtoir0mifsmie0ifms0f4498hdnawadw==--85C3B9E6116F464E393C241394CCC2BA"
  """
  @spec encrypt_wallet(String.t(), String.t(), String.t()) :: String.t()
  def encrypt_wallet(data, password, mnemonic_phrase) do
    encryptor = generate_encryptor(password, mnemonic_phrase)
    MessageEncryptor.encrypt_and_sign(encryptor, data)
  end

  @doc """
  Generates an encryptor used for encrypting
  the wallet data into the wallet file
  ## Example
      iex> WalletCrypto.generate_encryptor("password", "mnemonic_phrase")
      %{cipher: :aes_cbc256,
      secret: <<229, 209, 116, 218, 2, 239, 19, 210, 29, 83, 128, 25, 111, 107, 8,
      233, 92, 216, 154, 1, 41, 154, 98, 143, 145, 108, 4, 245, 225, 25, 8, 243>>,
      serializer: Cryptex.Serializers.ELIXIR,
      sign_secret: <<208, 238, 171, 88, 255, 215, 63, 123, 151, 66, 169, 113, 196,
      124, 55, 75, 163, 91, 234, 62, 212, 117, 143, 36, 45, 159, 54, 164, 240,
      207, 73, 104>>}
  """
  @spec generate_encryptor(String.t(), String.t()) :: Map.t()
  def generate_encryptor(password, mnemonic_phrase) do
    secret_key_base = :crypto.hash(:sha256, password) |> Base.encode16()
    encrypted_salt = :crypto.hash(:sha256, mnemonic_phrase) |> Base.encode16()
    secret = KeyGenerator.generate(secret_key_base, mnemonic_phrase)
    sign_secret = KeyGenerator.generate(secret_key_base, encrypted_salt)
    MessageEncryptor.new(secret, sign_secret)
  end
end
