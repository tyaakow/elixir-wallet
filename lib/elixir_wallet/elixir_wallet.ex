defmodule Wallet do
  require Logger

  @moduledoc """
  This module is used for creation of the Wallet file. To inspect it use
  WalletCrypto.decrypt_wallet("wallet_file_name", "password", "mnemonic_phrase")
  """

  @doc """
  Creates a wallet file
  ## Examples
      iex> Wallet.create_wallet("pass")
      Use the following phrase as additional authentication
      when accessing you wallet:

      whisper edit clump violin blame few ancient casual
      sand trip update spring
  """
  @spec create_wallet(String.t()) :: String.t()
  def create_wallet(password \\ "") do

    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    save_wallet_file(mnemonic_phrase, password)

    Logger.info("Your wallet was created.")
    Logger.info("Use the following phrase as additional authentication when accessing your wallet:")
    Logger.info(mnemonic_phrase)
  end

  @doc """
  Creates a wallet file from an existing mnemonic_phrase and password
  If the wallet was not password protected, just pass the mnemonic_phrase
  """
  @spec import_wallet(String.t(), String.t()) :: String.t()
  def import_wallet(mnemonic_phrase, password \\ "") do

    save_wallet_file(mnemonic_phrase, password)
    Logger.info("You have successfully imported a wallet")
  end

  @doc """
  Decrypts a file and displays it's mnemonic phrase 
  ## Examples
      iex> Wallet.load_wallet_file("wallet--2017-10-31-14-54-39", "password")
	  {:ok,
	  "spirit\r beach\r smile\r turn\r glance\r whale\r rack\r reflect\r marble\r cover\r enter\r pigeon"}
  """
  @spec load_wallet_file(String.t(), String.t()) :: Tuple.t()
  def load_wallet_file(file_path, password) do
    case File.read(file_path) do
      {:ok, encrypted_data} ->
        mnemonic = Cypher.decrypt(encrypted_data, password)
	{:ok, mnemonic}
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

  defp save_wallet_file(mnemonic_phrase, password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open(file, [:write])

    ## TODO: Get the password from the user
    encrypted = Cypher.encrypt(mnemonic_phrase, "password")
    IO.binwrite(file, encrypted)
    File.close(file)
  end

  @doc """
  Gets the public key
  ## Examples
      iex> Wallet.get_public_key("wallet--2017-10-31-14-54-39", "password")
	   "04187ACD56365459C0948953DD0D36A93E57A4C78C6E04E1E9DB10EA2C89FF2701DCC1AFB2C30F09ACE265EA11DAFE7E40591182F4EC3E7BB535305551D2A374CB"
  """
  @spec get_public_key(String.t(), String.t()) :: String.t()
  def get_public_key(file_path, password) do
   {_, mnemonic} = load_wallet_file(file_path, password)
     
   KeyPair.generate_root_seed(mnemonic)
   |> elem(1)
  end  
  
  @doc """
  Gets the wallet address
  ## Examples
      iex> Wallet.get_address("wallet--2017-10-31-14-54-39", "password")
	  "1NM51tw1MixFCe64g6ExhCEXnowEGrQ2DE"
  """
  @spec get_address(String.t(), String.t()) :: String.t()
  def get_address(file_path, password) do
   get_public_key(file_path, password)
   |> KeyPair.generate_wallet_address() 
  end
end
