defmodule GenerateIndexes do
  @moduledoc """
  Module for generating indexes used by the Mnemnonic module
  to generate a phrase fromo the wordlist
  """

  @doc """
  Generates random numbers(indexes) using entropy for guaranteed randomness
  ## Examples
      iex> GenerateIndexes.generate_indexes
      [674, 1135, 630, 1012, 624, 1428, 481, 1666, 693, 534, 1933, 628]
  """
  @spec generate_indexes() :: list()
  def generate_indexes() do
    entropy = :crypto.strong_rand_bytes(16)
    checksum_length = (byte_size(entropy) * 8) / 32 |> trunc()
    checksum = :crypto.hash(:sha256, entropy)
    |>Bits.to_binary_list()
    |>Enum.join()
    |>String.slice(0..checksum_length)

    entropy
    |> Bits.to_binary_list()
    |> Enum.join()
    |> Kernel.<>(checksum)
    |> split_bits_into_groups()
    |> parse_binary_list()
  end

  @doc """
  Splits the given string into groups of 11 bits each encoding
  a number from 0-2047, serving as an index into a wordlist.
  The result is a list of grups.
  ## Examples
      iex> GenerateIndexes.split_bits_into_groups("1011100011010100110110")
      ["10100110110", "10111000110"]

      iex> GenerateIndexes.split_bits_into_groups("1011100011010100110110" <> "1011001011")
      ["10100110110", "10111000110"]
  """
  @spec split_bits_into_groups(String.t()) :: list()
  def split_bits_into_groups(bits) do
    Regex.scan(~r/(.{1,11})/, bits)
    |> Enum.map(fn(elem) -> List.first(elem) end)
    |> Enum.reverse()
    |> List.delete_at(0)
  end

  @doc """
  Converts binary list (consisting of groups of 11 bits)
  to reversed byte list (consisting of number from 0 to 2047)
  ## Examples
      iex> GenerateIndexes.parse_binary_list(["10100110110", "10111000110"])
      [1478, 1334]
  """
  @spec parse_binary_list(List.t()) :: list()
  def parse_binary_list(list) do
    Enum.map(list, fn(binary) ->
      binary_to_byte(binary)
    end)
    |> List.flatten()
    |> Enum.reverse()
  end

  defp binary_to_byte(binary), do: Integer.parse(binary, 2) |> elem(0)
end
