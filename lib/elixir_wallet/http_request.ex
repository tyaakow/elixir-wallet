defmodule HttpRequest do
  def get_info(url, endpoint) do
    json =HTTPoison.get!(url <> endpoint)
  end
end
