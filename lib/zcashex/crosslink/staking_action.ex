defmodule Zcashex.Crosslink.StakingAction do
  @moduledoc """
  Decoder for Crosslink StakingAction payloads (VCrosslink / tx version 7,
  version group 0xFFFFFFFE).

  Wire format matches `StakingAction::read` in librustzcash at the pinned
  crosslink_monolith commit.
  """

  @kind_names %{
    1 => "CreateNewDelegationBond",
    2 => "BeginDelegationUnbonding",
    3 => "WithdrawDelegationBond",
    4 => "RetargetDelegationBond",
    5 => "ConvertFinalizerRewardToDelegationBond"
  }

  @doc "Human-readable name for a numeric kind."
  def kind_name(kind), do: Map.get(@kind_names, kind, "Unknown(#{kind})")

  @doc """
  Decode a StakingAction from the trailing bytes after the Ironwood bindingSig.
  Returns `{:ok, nil}` for a Null action, `{:ok, map}` for a real action,
  or `{:error, reason}`.
  """
  def decode(<<0, _::binary>>), do: {:ok, nil}

  def decode(<<tag::8, unique_pubkey::binary-size(32), signature::binary-size(64), rest::binary>>)
      when tag in 1..5 do
    case decode_variant(tag, rest) do
      {:ok, fields, _left} ->
        {:ok,
         Map.merge(fields, %{
           kind: tag,
           kind_name: kind_name(tag),
           unique_pubkey: unique_pubkey,
           signature: signature
         })}

      err ->
        err
    end
  end

  def decode(other), do: {:error, {:bad_tag_or_truncated, other}}

  defp decode_variant(
         1,
         <<bond_salt::binary-size(32), finalizer::binary-size(32), amount::little-unsigned-64,
           left::binary>>
       ) do
    {:ok, %{bond_salt: bond_salt, target_finalizer: finalizer, amount_zats: amount}, left}
  end

  defp decode_variant(2, left), do: {:ok, %{}, left}

  defp decode_variant(3, <<amount::little-unsigned-64, left::binary>>) do
    {:ok, %{amount_zats: amount}, left}
  end

  defp decode_variant(4, <<from::binary-size(32), to::binary-size(32), left::binary>>) do
    {:ok, %{from_finalizer: from, to_finalizer: to}, left}
  end

  defp decode_variant(
       5,
       <<bond_salt::binary-size(32), this_finalizer::binary-size(32),
         amount::little-unsigned-64, finalizer_sig::binary-size(64), left::binary>>
     ) do
  {:ok,
   %{
     bond_salt: bond_salt,
     this_finalizer: this_finalizer,
     amount_zats: amount,
     finalizer_signature: finalizer_sig
   }, left}
end

  defp decode_variant(tag, rest), do: {:error, {:bad_variant, tag, rest}}
end