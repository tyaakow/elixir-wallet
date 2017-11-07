defmodule HttpRequest do

  @doc """
  Makes a get request to the core
  ## Examples
      iex> HttpRequest.get_info("http://localhost:4000/", "info")
      %HTTPoison.Response{body: "{\"public_key\":\"048BFEDD7468A15D30590B1F14A98650D7FA2EE71355BAFDBFCC7003AA38AEBE55A634F72B9462298B03A266C7C68AEFCE0C2BE4DD80394A493130BEB9589450E5\",\"genesis_block_hash\":\"C061E48A6F7FB2634E0C012B168D41F4773A38BD9E5EA28E5BE7D04186127BA0\",\"difficulty_target\":1,\"current_block_version\":1,\"current_block_height\":0,\"current_block_hash\":\"C061E48A6F7FB2634E0C012B168D41F4773A38BD9E5EA28E5BE7D04186127BA0\"}",
      headers: [{"server", "Cowboy"}, {"date", "Fri, 03 Nov 2017 15:35:50 GMT"},
      {"content-length", "396"},
      {"content-type", "application/json; charset=utf-8"},
      {"cache-control", "max-age=0, private, must-revalidate"},
      {"x-request-id", "lc7p2fjssacf6h0elc5p58t3bnv5g0ok"},
      {"x-frame-options", "SAMEORIGIN"}, {"x-xss-protection", "1; mode=block"},
      {"x-content-type-options", "nosniff"}],
      request_url: "http://localhost:4000/info", status_code: 200}
  """
  @spec get_info(String.t(), String.t()) :: Map.t()
  def get_info(url, endpoint) do
    json = HTTPoison.get!(url <> endpoint)
  end
end
