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
  def create_wallet(password, pass_phrase \\ "") do

    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    if (pass_phrase != "") do 
      mnemonic_phrase_with_pass_phrase = mnemonic_phrase <> " " <> pass_phrase
      save_wallet_file(mnemonic_phrase_with_pass_phrase, password)
    else 
      save_wallet_file(mnemonic_phrase, password)
    end

    Logger.info("Your wallet was created.")
    Logger.info("Use the following phrase as additional authentication when accessing your wallet:")
    Logger.info(mnemonic_phrase)
  end

  @doc """
  Creates a wallet file from an existing mnemonic_phrase and password
  If the wallet was not password protected, just pass the mnemonic_phrase
  """
  @spec import_wallet(String.t(), String.t()) :: String.t()
  def import_wallet(mnemonic_phrase, password, pass_phrase \\ "") do
    save_wallet_file(mnemonic_phrase, password)
    Logger.info("You have successfully imported a wallet")
  end
 
  @doc """
  Decrypts a file and displays it's mnemonic phrase 
  Will only return a phrase if the password is correct 
  ## Examples
      iex> Wallet.load_wallet_file("wallet--2017-10-31-14-54-39", "password")
      {:ok,
      "spirit\r beach\r smile\r turn\r glance\r whale\r rack\r reflect\r marble\r cover\r enter\r pigeon"}
  """
  @spec load_wallet_file(String.t(), String.t()) :: Tuple.t()
  def load_wallet_file(file_path, password, pass_phrase \\ "") do
    case File.read(file_path) do
      {:ok, encrypted_data} ->
        mnemonic = Cypher.decrypt(encrypted_data, password)
        if (String.valid? mnemonic) do 
          mnemonic_list = String.split(mnemonic)
          pass_phrase_check = Enum.at(mnemonic_list, 12)
        case pass_phrase_check do 
          :nil -> {:ok , mnemonic}
          result -> 
            if result == pass_phrase do 
              mnemonic = String.replace(mnemonic, " " <> pass_phrase, "")          
              {:ok, mnemonic} 
            else 
              Logger.error("Invalid pass phrase")
              {:error, "Invalid pass phrase"}
            end
        end
        else 
          Logger.error("Invalid password")
          {:error, "Invalid password"}          
        end  
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
  Gets the public key
  Will only return a public key if the password is correct
  ## Examples
      iex> Wallet.get_public_key("wallet--2017-10-31-14-54-39", "password")
      {:ok, <<4, 210, 200, 166, 81, 219, 54, 116, 39, 64, 199, 57, 55, 152, 204, 119, 237,
      168, 175, 243, 132, 39, 71, 208, 94, 138, 190, 242, 78, 74, 141, 43, 58, 241,
      15, 19, 179, 45, 42, 79, 118, 24, 160, 20, 64, 178, 109, 124, 172, 127, ...>>}
  """
  @spec get_public_key(String.t(), String.t()) :: Tuple.t()
  def get_public_key(file_path, password, pass_phrase \\ "") do
    {validation, reply} = load_wallet_file(file_path, password, pass_phrase)
          
    case validation do
      :ok -> 
        public_key =
        KeyPair.generate_root_seed(reply, pass_phrase)
        |> elem(1)
        {:ok, public_key}
      :error -> {:error, reply}
    end  
  end 
  
  @doc """
  Gets the wallet address
  Will only return an address if the password is correct
  ## Examples
      iex> Wallet.get_address("wallet--2017-10-31-14-54-39", "password")
      {:ok, "1NM51tw1MixFCe64g6ExhCEXnowEGrQ2DE"}
  """
  @spec get_address(String.t(), String.t()) :: Tuple.t()
  def get_address(file_path, password, pass_phrase \\ "") do
    {validation, reply} = get_public_key(file_path, password, pass_phrase)

    case validation do
      :ok -> 
        address = KeyPair.generate_wallet_address(reply) 
        {:ok, address}
      :error -> {:error, reply}
    end
  end

  @doc """
  Gets the private key
  Will only return a private key if the password is correct
  ## Examples
      iex> Wallet.get_private_key("wallet--2017-10-31-14-54-39", "password")
      {:ok, <<100, 208, 92, 132, 43, 104, 6, 55, 125, 18, 18, 215, 98, 8, 245, 12, 78, 92,
      89, 115, 59, 231, 28, 142, 137, 119, 62, 19, 102, 238, 171, 185>>}
  """
  @spec get_private_key(String.t(), String.t()) :: Tuple.t()
  def get_private_key(file_path, password, pass_phrase \\ "") do
    {validation, reply} = load_wallet_file(file_path, password, pass_phrase)
     
    case validation do
      :ok -> 
        private_key =
        KeyPair.generate_root_seed(reply, pass_phrase)
        |> elem(0)
        {:ok, private_key}
      :error -> {:error, reply}
    end  
  end

  defp save_wallet_file(mnemonic_phrase, password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open(file, [:write])

    encrypted = Cypher.encrypt(mnemonic_phrase, password)
    IO.binwrite(file, encrypted)
    File.close(file)
  end
end
