defmodule HttpRequestTest do
  use ExUnit.Case
  doctest ElixirWallet

  test "validate HTTP request" do
    url = "http://localhost:4000/"
    endpoint = "info"
    request = HttpRequest.get_info(url, endpoint)
    {:ok, response} = Poison.decode(request.body)
    assert response == %{"public_key"=>"04BEC8ABE0878CD0A7C4741A5F48EA0D36553754C03CC43DED49868E5B139202B7D364924A5077881C1B46E984E13DA48573E382E32D143F9657FEB88F08782353",
                         "genesis_block_hash"=> "C061E48A6F7FB2634E0C012B168D41F4773A38BD9E5EA28E5BE7D04186127BA0",
                         "difficulty_target" => 1,
                         "current_block_version" => 1,
                         "current_block_height" => 0,
                         "current_block_hash" => "C061E48A6F7FB2634E0C012B168D41F4773A38BD9E5EA28E5BE7D04186127BA0"}
  end
end
