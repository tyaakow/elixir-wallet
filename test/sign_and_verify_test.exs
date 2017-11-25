defmodule SigningAndVerifyingTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate signing and verifying transaction 1" do
    message = <<0,1>>
    privkey_bin = <<127, 192, 0, 152, 74, 57, 205, 167, 81, 245, 120, 212, 148, 133, 223, 98, 103, 153, 195, 51, 47, 5, 241, 37, 50, 99, 85, 77, 69, 249, 32, 203>>

    signature = Signing.sign(message, privkey_bin)
   
    {_, public_key} = Base.decode16("04C232B177F8EDB01290C3FEDBE5231BDF67AEF24F4C7947B06A298C5CDA573E16ADB2A621525C44222D29E113B315508B32364584EDF99F8DE7E0D7C2D2A871AB")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 2" do
    message = <<0,1,2>>
    privkey_bin = <<126, 32, 135, 160, 52, 26, 7, 154, 140, 91, 243, 46, 107, 203, 187, 2, 95, 72, 252, 160, 238, 52, 171, 132, 252, 79, 178, 212, 176, 23, 60, 151>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04BCD5FBFE8563FD97AFAEBAEB3B81CF22D10AD89FC905ECF5BFCE85849E417458100A66C442A942DC512181A4563AFFF3604F1F7D553FBF1A50B788F9102D1DA8")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 3" do
    message = <<0,1,2,3>>
    privkey_bin = <<5, 216, 31, 11, 146, 207, 26, 236, 109, 57, 89, 133, 56, 23, 169, 87, 131, 153, 74, 102, 125, 36, 134, 116, 84, 5, 101, 2, 25, 33, 77, 199>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("044A4435503E7E324C9AE6B966C9F43CEECCDEAE192969AD2C6E9E5963AC65E62C9C21D1CC395E8C8639B30975471B588191A67C084F0AAD08D63E6F33CA47D348")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 4" do
    message = <<0,1,4>>
    privkey_bin = <<231, 9, 82, 160, 47, 135, 169, 209, 203, 123, 50, 246, 91, 24, 224, 149, 238, 213, 241, 178, 218, 197, 20, 227, 77, 80, 177, 240, 26, 16, 244, 24>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04B9A2BF7834AF55B1BC4356F74A11D8A8D1AA4CFC9635699FCE71C2F9186B5EC07EE55CC8452A9C3535589EA12D792FEA4E907C2FE0E1E0AEAF91D86E033607C1")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end    

  test "validate signing and verifying transaction 5" do
    message = <<0,1,5,6>>
    privkey_bin = <<219, 224, 235, 1, 100, 205, 93, 94, 167, 11, 205, 251, 190, 141, 57, 104, 254, 92, 44, 97, 10, 154, 12, 46, 150, 45, 79, 30, 18, 116, 203, 245>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("048BF1724D1C9695D74D3948E59C89EDC1156FF9159A073507C76E99BC45F2008CC05E7BBC7F50E00311EFF62D46C8F66C4DB39D77274F0F2D0F7DE5606E8A16E8")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 6" do
    message = <<0,1,7>>
    privkey_bin = <<216, 14, 54, 73, 204, 159, 193, 205, 24, 118, 211, 98, 119, 176, 93, 65, 16, 248, 139, 39, 79, 95, 195, 43, 243, 122, 87, 2, 187, 115, 136, 198>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04F5541EFE1CF9FC5A2DB228A434CFBA4A7110E259349444ED486FE414A228C3EFA482A37FE99839C9729FC4EF8F25E89B9246B25B8A62C6D78EA56630E8878190")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 7" do
    message = <<0,1,8,9>>
    privkey_bin = <<224, 135, 42, 190, 243, 83, 235, 27, 219, 233, 81, 4, 228, 88, 3, 5, 98, 68, 53, 98, 222, 211, 189, 156, 17, 12, 126, 5, 200, 69, 10, 179>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04EFE05D2A147BC0517C17699AD823F959146A74377E9915FF469F7ACFF3E885C1275807C5BF2CF149710DC47EB73BFEF5A8475BFDC59BCCA47D7C6261639B3218")
    verification = Signing.verify(message, signature, public_key)
    assert verification == true
  end

  test "validate signing and verifying transaction 8" do
    message = <<0,1,12,13>>
    privkey_bin = <<82, 21, 70, 136, 30, 228, 206, 223, 74, 151, 175, 159, 72, 127, 156, 40, 92, 82, 169, 188, 153, 120, 22, 17, 131, 217, 32, 63, 96, 167, 87, 142>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04AB8D2D6C3AC611317612A7E5F624100A798398BB9A2E4D2BF08861AC64EFD6D63603ABDFA0967AD635846C912DABACF0D426EE3EF903765F2EC06A8B08B098E2")
    public_key = public_key <> "zxc"
    verification = Signing.verify(message, signature, public_key)
    assert verification == false
  end

  test "validate signing and verifying transaction 9" do
    message = <<0,1,14>>
    privkey_bin = <<235, 65, 64, 124, 123, 100, 227, 206, 59, 89, 29, 45, 51, 251, 64, 151, 15, 16, 188, 221, 100, 249, 221, 142, 180, 158, 69, 32, 123, 102, 159, 22>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("04324A89114A32E5B6D72300744645F92E4A545E7FC8514B25A105E7974739D71D1A2B9B02D8086F6832A861F046025EBC6B25692D097F2CFE33DB6D82B4F66092")
    public_key = public_key <> "zxc"
    verification = Signing.verify(message, signature, public_key)
    assert verification == false
  end

  test "validate signing and verifying transaction 10" do
    message = <<0,1,15,16>>
    privkey_bin = <<209, 50, 144, 148, 224, 118, 143, 247, 201, 212, 168, 134, 163, 112, 187, 132, 210, 179, 67, 75, 198, 55, 138, 243, 61, 249, 48, 84, 216, 222, 255, 180>>

    signature = Signing.sign(message, privkey_bin)

    {_, public_key} = Base.decode16("046E9AD55209E331465CF9DA3C26D7A096BA292354651D0404C5C266655FE884992DC11F9A916595A53940562088DCE48CC7C5E635BAB91F8E372CCDFA4484EB1A")
    public_key = public_key <> "zxc"
    verification = Signing.verify(message, signature, public_key)
    assert verification == false
  end
end
