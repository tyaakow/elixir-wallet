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
  def to_binary_list(binary) when is_binary(binary) do
    to_binary_list(binary, [])
  end

  defp to_binary_list(<<bit::size(1), bits::bitstring>>, acc) do
    to_binary_list(bits, [bit | acc])
  end

  defp to_binary_list(<<>>, acc), do: Enum.reverse(acc)

end
