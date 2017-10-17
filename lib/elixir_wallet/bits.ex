defmodule Bits do
  @moduledoc """
  Module for converting a bitstring to a list of bits
  """

  @doc """
  Loops through the bitstring and converts it to binary list
  ## Examples
      iex> Bits.to_binary_string(<<1>>)
      [0, 0, 0, 0, 0, 0, 0, 1]

      iex> Bits.to_binary_list(<<45, 234>>)
      [0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0]
  """
  @spec to_binary_list(Bitstring.t()) :: []
  def to_binary_list(str) when is_binary(str) do
    to_binary_list(str, [])
  end

  defp to_binary_list(<<b :: size(1), bits :: bitstring>>, acc) when is_bitstring(bits) do
    to_binary_list(bits, [b | acc])
  end

  defp to_binary_list(<<>>, acc), do: acc |> Enum.reverse

end
