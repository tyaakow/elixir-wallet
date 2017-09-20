defmodule GenerateIndexes do

  def generate_indexes do
    sliced = :crypto.hash(:sha256, entropy = :crypto.strong_rand_bytes(16))
    |>Bits.extract
    |>Enum.join
    |>String.slice(0,4)
    conc_bits = Enum.join(Bits.extract(entropy)) <> sliced
    parse_binary_list(get_sliced_parts(conc_bits))
  end

  def get_sliced_parts(str) do
    get_sliced_parts(str, 0, 11, String.length(str), [])
  end

  defp get_sliced_parts(str, start, length, total_length, result) when start * length <= total_length do
    get_sliced_parts(str, start + 1, length, total_length, [String.slice(str, start * length, length) | result])
  end

  defp get_sliced_parts(_str, _start, _length, _total_length, result) do
    List.delete_at(result, 0)
  end

  def parse_binary_list(list) do
    parsed_list = []
    parsed_list = for n <- list do
      {value,_} = Integer.parse(n,2)
      [value | parsed_list]
    end

    parsed_list |> List.flatten |> Enum.reverse
  end

end
