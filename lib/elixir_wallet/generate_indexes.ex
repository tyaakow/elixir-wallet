defmodule GenerateIndexes do
  @moduledoc """
  Module for generating indexes used by the Mnemnonic module
  to generate a phrase from the wordlist

  The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is improved
  but the sentence length increases. We refer to the initial entropy length as ENT.
  The allowed size of ENT is 128-256 bits.

  First, an initial entropy of ENT bits is generated. A checksum is generated by taking the first

  ENT / 32

  bits of its SHA256 hash. This checksum is appended to the end of the initial entropy.
  Next, these concatenated bits are split into groups of 11 bits,
  each encoding a number from 0-2047, serving as an index into a wordlist.
  Finally, we convert these numbers into words and use the joined words as a mnemonic sentence.
  The following table describes the relation between the initial entropy length (ENT),
  the checksum length (CS) and the length of the generated mnemonic sentence (MS) in words.

  ## Example
      CS = ENT / 32
      MS = (ENT + CS) / 11

      |  ENT  | CS | ENT+CS |  MS  |
      +-------+----+--------+------+
      |  128  |  4 |   132  |  12  |
      |  160  |  5 |   165  |  15  |
      |  192  |  6 |   198  |  18  |
      |  224  |  7 |   231  |  21  |
      |  256  |  8 |   264  |  24  |
  """

  ## 128 bits in bytes
  @entropy_byte_size 16

  @doc """
  Generates random numbers(indexes) using entropy for guaranteed randomness
  ## Examples
      iex> GenerateIndexes.generate_indexes()
      [674, 1135, 630, 1012, 624, 1428, 481, 1666, 693, 534, 1933, 628]
  """
  @spec generate_indexes() :: List.t()
  def generate_indexes() do
    entropy = generate_entropy(@entropy_byte_size)
    checksum = generate_checksum(entropy, @entropy_byte_size)

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
  @spec split_bits_into_groups(String.t()) :: List.t()
  def split_bits_into_groups(string_bits) do
    split(string_bits)
  end

  @doc """
  Converts binary list (consisting of groups of 11 bits)
  to byte list (consisting of number from 0 to 2047)
  ## Examples
      iex> GenerateIndexes.parse_binary_list(["10100110110", "10111000110"])
      [1478, 1334]
  """
  @spec parse_binary_list(List.t()) :: List.t()
  def parse_binary_list(list) do
    Enum.map(list, fn(binary) ->
      binary_to_byte(binary)
    end)
  end
  def binary_to_byte(binary), do: Integer.parse(binary, 2) |> elem(0)



  ## Private functions

  defp generate_entropy(entropy_byte_size) do
    :crypto.strong_rand_bytes(entropy_byte_size)
  end

  defp generate_checksum(entropy, entropy_byte_size) do
    checksum_length = ((entropy_byte_size * 8) / 32) |> trunc()

    ## Take the first 4 bits
    :crypto.hash(:sha256, entropy)
    |> Bits.to_binary_list()
    |> Enum.join()
    |> String.slice(0..(checksum_length-1))
  end

  defp split(string_bits) do
    split(string_bits, [])
  end
  defp split(<<part::binary-11, rest::binary>>, acc) do
    split(rest, [part | acc])
  end
  defp split("", acc), do: Enum.reverse(acc)

end
