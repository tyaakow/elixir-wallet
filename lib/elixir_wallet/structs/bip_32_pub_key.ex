defmodule Structs.Bip32PubKey do

  # Network versions
  @mainnet_ext_pub_key_version  0x0488B21E
  @testnet_ext_pub_key_version  0x043587CF

  defstruct [:version, :depth, :f_print, :child_num, :chain_code, :key]

  def create(:mainnet) do
    default(@mainnet_ext_priv_key_version)
  end
  def create(:testnet) do
    default(@testnet_ext_priv_key_version)
  end
  defp default(version) do
    %Structs.Bip32PubKey{version: version,
                  depth: 0,
                  f_print: <<0::32>>,
                  child_num: 0,
                  chain_code: <<0>>,
                  key: <<0>>}
  end
end
