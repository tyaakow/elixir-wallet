defmodule ElixirApi.Router do
  use ElixirApi.Web, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :put_secure_browser_headers
  end

  scope "/", ElixirApi do
    pipe_through :browser # Use the default browser stack
    get "/get_info", GetInfoController, :get_info
  end

  # Other scopes may use custom stacks.
  # scope "/api", ElixirApi do
  #   pipe_through :api
  # end
end
