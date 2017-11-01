defmodule PublicKeyAndAddressTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate master public key and address 1" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-48","password")
    assert mnemonic == {:ok,
    "bulk\r property\r loop\r pen\r fuel\r wild\r gorilla\r say\r pond\r rigid\r torch\r budget"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-48","password")
    assert public_key == "04C232B177F8EDB01290C3FEDBE5231BDF67AEF24F4C7947B06A298C5CDA573E16ADB2A621525C44222D29E113B315508B32364584EDF99F8DE7E0D7C2D2A871AB"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-48","password")
 	assert address == "1JWrJcwMRbxXk68nmA2gQ9Ly4BT7GhuAyt"
  end

  test "validate master public key and address 2" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-57","password")
    assert mnemonic == {:ok,
   "able\r actress\r bring\r rebuild\r clean\r timber\r flash\r grace\r tribe\r trial\r income\r brother"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-57","password")
    assert public_key == "04BCD5FBFE8563FD97AFAEBAEB3B81CF22D10AD89FC905ECF5BFCE85849E417458100A66C442A942DC512181A4563AFFF3604F1F7D553FBF1A50B788F9102D1DA8"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-57","password")
 	assert address == "1PruVefxahxDZcWiVYU7nYZxrMHKS97qvW"
  end

   test "validate master public key and address 3" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-58","password")
    assert mnemonic == {:ok,
    "tenant\r thrive\r marble\r magnet\r chief\r taxi\r enhance\r verb\r session\r saddle\r venue\r during"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-58","password")
    assert public_key == "044A4435503E7E324C9AE6B966C9F43CEECCDEAE192969AD2C6E9E5963AC65E62C9C21D1CC395E8C8639B30975471B588191A67C084F0AAD08D63E6F33CA47D348"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-58","password")
 	assert address == "12C72EW63jLCaDXfmqk6DcjUoUykdD6Xhn"
  end

  test "validate master public key and address 4" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-35-59","password")
    assert mnemonic == {:ok,
    "drum\r pledge\r man\r fame\r sort\r favorite\r doll\r color\r device\r remove\r angry\r jelly"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-35-59","password")
    assert public_key == "04B9A2BF7834AF55B1BC4356F74A11D8A8D1AA4CFC9635699FCE71C2F9186B5EC07EE55CC8452A9C3535589EA12D792FEA4E907C2FE0E1E0AEAF91D86E033607C1"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-35-59","password")
 	assert address == "13F4jMJmUFV9rmoWgGND1jBfwgQbTKpPuv"
  end

  test "validate master public key and address 5" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-0","password")
    assert mnemonic == {:ok,
    "year\r wage\r suggest\r cream\r good\r length\r umbrella\r ridge\r winter\r giant\r blast\r improve"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-0","password")
    assert public_key == "048BF1724D1C9695D74D3948E59C89EDC1156FF9159A073507C76E99BC45F2008CC05E7BBC7F50E00311EFF62D46C8F66C4DB39D77274F0F2D0F7DE5606E8A16E8"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-0","password")
 	assert address == "1LfdSWu1eEijd6GzTh8SASMsTU8wDgbtfB"
  end

  test "validate master public key and address 6" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-1","password")
    assert mnemonic == {:ok,
    "inhale\r step\r culture\r mesh\r barrel\r dice\r deputy\r rural\r sweet\r spend\r dry\r quality"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-1","password")
    assert public_key == "04F5541EFE1CF9FC5A2DB228A434CFBA4A7110E259349444ED486FE414A228C3EFA482A37FE99839C9729FC4EF8F25E89B9246B25B8A62C6D78EA56630E8878190"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-1","password")
 	assert address == "1Ne53VaygH84k8CiVhWEF9id992yGuaDWN"
  end

  test "validate master public key and address 7" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-2","password")
    assert mnemonic =={:ok,
    "slot\r memory\r drink\r square\r yard\r student\r erupt\r chronic\r solution\r pass\r furnace\r dad"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-2","password")
    assert public_key == "04EFE05D2A147BC0517C17699AD823F959146A74377E9915FF469F7ACFF3E885C1275807C5BF2CF149710DC47EB73BFEF5A8475BFDC59BCCA47D7C6261639B3218"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-2","password")
 	assert address == "1L2AWwJ59rLHAGqj7zPMHoWsrVHdb4Gthr"
  end

  test "validate master public key and address 8" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-3","password")
    assert mnemonic == {:ok,
    "all\r pride\r wish\r loyal\r version\r evoke\r neck\r question\r melt\r thought\r ladder\r club"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-3","password")
    assert public_key == "04AB8D2D6C3AC611317612A7E5F624100A798398BB9A2E4D2BF08861AC64EFD6D63603ABDFA0967AD635846C912DABACF0D426EE3EF903765F2EC06A8B08B098E2"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-3","password")
 	assert address == "16AeMpdZyQsGPTrBoqG21uSDWvwecexEhn"
  end

  test "validate master public key and address 9" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-36-20","password")
    assert mnemonic == {:ok,
    "solve\r tourist\r puzzle\r wasp\r wheat\r syrup\r crunch\r unusual\r boy\r maid\r ill\r click"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-36-20","password")
    assert public_key == "04324A89114A32E5B6D72300744645F92E4A545E7FC8514B25A105E7974739D71D1A2B9B02D8086F6832A861F046025EBC6B25692D097F2CFE33DB6D82B4F66092"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-36-20","password")
 	assert address == "195QyobsNRwTn56HGcoFp4NzWUs1JwSoQv"
  end

  test "validate master public key and address 10" do
    mnemonic=Wallet.load_wallet_file("test/test_wallets/wallet--2017-11-1-16-37-15","password")
    assert mnemonic == {:ok,
    "leave\r quick\r have\r cash\r insane\r resemble\r juice\r duty\r vault\r poem\r ramp\r spirit"}
    public_key=Wallet.get_public_key("test/test_wallets/wallet--2017-11-1-16-37-15","password")
    assert public_key == "046E9AD55209E331465CF9DA3C26D7A096BA292354651D0404C5C266655FE884992DC11F9A916595A53940562088DCE48CC7C5E635BAB91F8E372CCDFA4484EB1A"
 	address=Wallet.get_address("test/test_wallets/wallet--2017-11-1-16-37-15","password")
 	assert address == "19DNsWCfHAMx3H9iHxDK8V4gucuSatppMH"
  end

  end