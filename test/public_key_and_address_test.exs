defmodule PublicKeyAndAddressTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate master public key and address 1" do
    private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
  end

  test "validate master public key and address 2" do
    private_key_hex = "BC4300B0550B4CD3C141787DA100F14C3BBF1DD137F5B3DBD7CF403501270600"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "040062311DD98C991BB7EA254969273E8780E60926FCD5D8B927583F00F1362880CC85D2BF3106FAE1DBCB1EC2146DB236110C84304EAEFA152F2C89DE98E1AF92"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1AuoyK3Kq8rQ9umw5FpPHQPaDGFTVceBUA"
  end

  test "validate master public key and address 3" do
    private_key_hex = "699FA657A10800B33F46F81F8D91B9BAFC68C6CEAD1918C02FE5C36579D372D5"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "04E8ABC902A5BAA259AEFAFE16AA3BA5A0ADB1408440A37804D6983997688C81712CAED5A9B99A0D9CF7BC1E005773B298F09720F507660E567CEA8C46C23AFAAC"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1DkASREvmL4KVkTrPEJJ7ESes2Nb4PpChm"
  end

  test "validate master public key and address 4" do
    private_key_hex = "C891DDECFE7022DA8C16A91237F057343A032AFACA35BC7BC2920BB44E86846A"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "040EEA2F51760E5332D2200CD2AFF29922D08A6CC2066A08D2ADF0548AE2014753A44355BFE4DB4556DCE3B4865C297EC22841A98DE5CD596A7E75D7CC290E1F0C"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1L5bKx76C9QeXdFojue5m8KAgtTgGW6EnZ"
  end

  test "validate master public key and address 5" do
    private_key_hex = "E8FDD9EC10A20F1F9D29A43312BFE3A245AB01D3E721D27DCDC69B82B11AFE03"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "043DFF8563882A3E66E84FEB90BFB9FACF80332DD6EB5972482472EDA319828114BDCF807B94C0E389CA285EEF064C0DF4BB188406E50E780427E35BAB893D3217"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1PBCsF6Fqn1FRHqaNbYKjzjCtrLpcuADot"
  end

  test "validate master public key and address 6" do
    private_key_hex = "29072D08E66D501223FAE169AA640AA3B8578C2A99CEA8278630788A13DD1FDE"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "04C9D3051C53339040917770A1E04CE6E2A9638DE5BCBCB40FBEC33615A7B3B767235AEF0DE0189A785EAD9ED455F6A6163AF3E15B8C60911F05251172DB18ACC5"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1AQRJkftCgJ8eeApUFceFMo9YpUEB9tPhS"
  end

  test "validate master public key and address 7" do
    private_key_hex = "5B962E356BE58553EBDCFEC03E80D80675CA8A644AD4EAAB85DB51446F1D5FF3"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "04B0E9E92F95E173B920E4CC32E482B23CC38BF26C99852C7959DDC4698E3334764145ABEB20A365B67AC8B51B67756955E62CD6CCD26B6C6BC3A7CF635E272903"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1PPwkXoPreMTs69aScGiesoTudap7M19Es"
  end

  test "validate master public key and address 8" do
    private_key_hex = "CCDB0D0855AA2E0D4D9F23E438F1037176E3204831921B2364B761CC7EFAEE7E"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "0488921A1FF2AA5BB571486AA7588655C6C6D1A68FBB3E0908659ED797034C5EFB5129084FF94F442C8D1FF3BE461FCAA1FD17752F703F3AA045B7F66DFEDF8A7E"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "19bmCy3jjuB1X8wks9rTCHkaprD2hPtG3S"
  end

  test "validate master public key and address 9" do
    private_key_hex = "22A07311553570F8D1F2B18778B2BA5CE24052C391FC4342B90183F77EBF9CB7"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "0416FC79A80627363BBDD8A0CC059DAC6529982D0AE78B560AF02828E0C0D9070A6BF03CE95ACB49B9BDFCC8A0D2D0C0C65854E92E8BC5019A604B3486F251D148"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "13xoFme8mGzVxr3o2J4wpHtEqbfML2CtEd"
  end

  test "validate master public key and address 10" do
    private_key_hex = "B26E795EB334811C52E6946A8089C88358849F27CFA647C1191C316593B6D7BC"
    {:ok, private_key_bin} = private_key_hex |> Base.decode16()
    <<pivate_key_dec::size(256)>> = private_key_bin
    public_key_bin = KeyPair.generate_master_public_key(pivate_key_dec)
    public_key_hex = public_key_bin |> Base.encode16()
    assert public_key_hex == "041E2302BB6B2AD1222DA0E8D12FF0DD7705EA476E9E6CD589D389A4A2E2BF00A682C0FF225578E2A2DBAA39D00993C40E1E8A352179A359B910380E8EFE0BAF3D"
    address = KeyPair.generate_wallet_address(public_key_hex)
    assert address == "1G2T2Ker5AA9V7e7UMdj2umkGhYaXEAmit"
  end

end
