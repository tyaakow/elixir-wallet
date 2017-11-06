defmodule ElixirApi.GetInfoController do
  use ElixirApi.Web, :controller

 def get_info(conn, _params) do
   url = "http://localhost:4000/"
   endpoint = "info"
   map = HTTPoison.get!(url <> endpoint)
   map = Poison.decode!(map.body)

  json conn, %{public_key: map["public_key"],
               genesis_block_hash: map["genesis_block_hash"],
               difficulty_target: map["difficulty_target"],
               current_block_version: map["current_block_version"],
               current_block_height: map["current_block_height"],
               current_block_hash: map["current_block_hash"]
              }
 end
end
