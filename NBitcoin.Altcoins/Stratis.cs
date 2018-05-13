using NBitcoin.DataEncoders;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;

namespace NBitcoin.Altcoins
{
	public class Stratis : NetworkSetBase
	{
		public static Stratis Instance { get; } = new Stratis();

		public override string CryptoCode => "STRAT";

		private Stratis()
		{

		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class StratisConsensusFactory : ConsensusFactory
		{
			private StratisConsensusFactory()
			{
			}

			public static StratisConsensusFactory Instance { get; } = new StratisConsensusFactory();

			public override Block CreateBlock()
			{
				return new StratisBlock(new BlockHeader());
			}

			public override Transaction CreateTransaction()
			{
				return new StratisTransaction(this);
			}
		}

		public class StratisBlockSignature : IBitcoinSerializable
		{
			protected bool Equals(StratisBlockSignature other)
			{
				return Equals(signature, other.signature);
			}

			public override bool Equals(object obj)
			{
				if (ReferenceEquals(null, obj)) return false;
				if (ReferenceEquals(this, obj)) return true;
				if (obj.GetType() != this.GetType()) return false;
				return Equals((StratisBlockSignature)obj);
			}

			public override int GetHashCode()
			{
				return (signature?.GetHashCode() ?? 0);
			}

			public StratisBlockSignature()
			{
				this.signature = new byte[0];
			}

			private byte[] signature;

			public byte[] Signature
			{
				get
				{
					return signature;
				}
				set
				{
					signature = value;
				}
			}

			internal void SetNull()
			{
				signature = new byte[0];
			}

			public bool IsEmpty()
			{
				return !this.signature.Any();
			}

			public static bool operator ==(StratisBlockSignature a, StratisBlockSignature b)
			{
				if (System.Object.ReferenceEquals(a, b))
					return true;

				if (((object)a == null) || ((object)b == null))
					return false;

				return a.signature.SequenceEqual(b.signature);
			}

			public static bool operator !=(StratisBlockSignature a, StratisBlockSignature b)
			{
				return !(a == b);
			}

			#region IBitcoinSerializable Members

			public void ReadWrite(BitcoinStream stream)
			{
				stream.ReadWriteAsVarString(ref signature);
			}

			#endregion

			public override string ToString()
			{
				return Encoders.Hex.EncodeData(this.signature);
			}
		}

		public class StratisBlock : Block
		{
			public StratisBlock(BlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return StratisConsensusFactory.Instance;
			}

			public override void ReadWrite(BitcoinStream stream)
			{
				base.ReadWrite(stream);
				stream.ReadWrite(ref this.blockSignature);
			}

			public static bool BlockSignature = false;

			// block signature - signed by one of the coin base txout[N]'s owner
			private StratisBlockSignature blockSignature = new StratisBlockSignature();

			public StratisBlockSignature BlockSignatur
			{
				get { return this.blockSignature; }
				set { this.blockSignature = value; }
			}
		}

		public class StratisTransaction : Transaction
		{
			public StratisTransaction(ConsensusFactory consensusFactory)
			{
				_Factory = consensusFactory;
			}

			ConsensusFactory _Factory;
			public override ConsensusFactory GetConsensusFactory()
			{
				return _Factory;
			}

			/// <summary>
			/// POS Timestamp
			/// </summary>
			public uint Time { get; set; } = Utils.DateTimeToUnixTime(DateTime.UtcNow);

			public override void ReadWrite(BitcoinStream stream)
			{		
				var witSupported = (((uint)stream.TransactionOptions & (uint)TransactionOptions.Witness) != 0) &&
										stream.ProtocolCapabilities.SupportWitness;

				if (stream.Serializing)
					SerializeTxn(stream, witSupported);
				else
					DeserializeTxn(stream, witSupported);				
			}

			private void DeserializeTxn(BitcoinStream stream, bool witSupported)
			{
				byte flags = 0;

				UInt32 nVersionTemp = 0;
				stream.ReadWrite(ref nVersionTemp);

				// POS time stamp
				uint nTimeTemp = 0;
				stream.ReadWrite(ref nTimeTemp);

				TxInList vinTemp = new TxInList();
				TxOutList voutTemp = new TxOutList();

				/* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
				stream.ReadWrite<TxInList, TxIn>(ref vinTemp);

				var hasNoDummy = (nVersionTemp & NoDummyInput) != 0 && vinTemp.Count == 0;
				if (witSupported && hasNoDummy)
					nVersionTemp = nVersionTemp & ~NoDummyInput;

				if (vinTemp.Count == 0 && witSupported && !hasNoDummy)
				{
					/* We read a dummy or an empty vin. */
					stream.ReadWrite(ref flags);
					if (flags != 0)
					{
						/* Assume we read a dummy and a flag. */
						stream.ReadWrite<TxInList, TxIn>(ref vinTemp);
						vinTemp.Transaction = this;
						stream.ReadWrite<TxOutList, TxOut>(ref voutTemp);
						voutTemp.Transaction = this;
					}
					else
					{
						/* Assume read a transaction without output. */
						voutTemp = new TxOutList();
						voutTemp.Transaction = this;
					}
				}
				else
				{
					/* We read a non-empty vin. Assume a normal vout follows. */
					stream.ReadWrite<TxOutList, TxOut>(ref voutTemp);
					voutTemp.Transaction = this;
				}
				if (((flags & 1) != 0) && witSupported)
				{
					/* The witness flag is present, and we support witnesses. */
					flags ^= 1;
					Witness wit = new Witness(vinTemp);
					wit.ReadWrite(stream);
				}
				if (flags != 0)
				{
					/* Unknown flag in the serialization */
					throw new FormatException("Unknown transaction optional data");
				}
				LockTime lockTimeTemp = LockTime.Zero;
				stream.ReadWriteStruct(ref lockTimeTemp);

				this.Version = nVersionTemp;
				this.Time = nTimeTemp; // POS Timestamp
				vinTemp.ForEach(i => this.AddInput(i));
				voutTemp.ForEach(i => this.AddOutput(i));
				this.LockTime = lockTimeTemp;				
			}

			private void SerializeTxn(BitcoinStream stream, bool witSupported)
			{
				byte flags = 0;
				var version = (witSupported && (this.Inputs.Count == 0 && this.Outputs.Count > 0)) ? this.Version | NoDummyInput : this.Version;
				stream.ReadWrite(ref version);

				// POS Timestamp
				var time = this.Time;
				stream.ReadWrite(ref time);

				if (witSupported)
				{
					/* Check whether witnesses need to be serialized. */
					if (HasWitness)
					{
						flags |= 1;
					}
				}
				if (flags != 0)
				{
					/* Use extended format in case witnesses are to be serialized. */
					TxInList vinDummy = new TxInList();
					stream.ReadWrite<TxInList, TxIn>(ref vinDummy);
					stream.ReadWrite(ref flags);
				}
				TxInList vin = this.Inputs;				
				stream.ReadWrite<TxInList, TxIn>(ref vin);
				vin.Transaction = this;
				TxOutList vout = this.Outputs;
				stream.ReadWrite<TxOutList, TxOut>(ref vout);
				vout.Transaction = this;
				if ((flags & 1) != 0)
				{
					Witness wit = new Witness(this.Inputs);
					wit.ReadWrite(stream);
				}
				LockTime lockTime = this.LockTime;
				stream.ReadWriteStruct(ref lockTime);
			}

			public static StratisTransaction ParseJson(string tx)
			{
				JObject obj = JObject.Parse(tx);
				StratisTransaction stratTx = new StratisTransaction(Stratis.StratisConsensusFactory.Instance);
				DeserializeFromJson(obj, ref stratTx);

				return stratTx;
			}

			private static void DeserializeFromJson(JObject json, ref StratisTransaction tx)
			{
				tx.Version = (uint)json.GetValue("version");
				tx.Time = (uint)json.GetValue("time");
				tx.LockTime = (uint)json.GetValue("locktime");

				var vin = (JArray)json.GetValue("vin");
				for (int i = 0; i < vin.Count; i++)
				{
					var jsonIn = (JObject)vin[i];
					var txin = new TxIn();
					tx.Inputs.Add(txin);

					var script = (JObject)jsonIn.GetValue("scriptSig");
					if (script != null)
					{
						txin.ScriptSig = new Script(Encoders.Hex.DecodeData((string)script.GetValue("hex")));
						txin.PrevOut.Hash = uint256.Parse((string)jsonIn.GetValue("txid"));
						txin.PrevOut.N = (uint)jsonIn.GetValue("vout");
					}
					else
					{
						var coinbase = (string)jsonIn.GetValue("coinbase");
						txin.ScriptSig = new Script(Encoders.Hex.DecodeData(coinbase));
					}

					txin.Sequence = (uint)jsonIn.GetValue("sequence");

				}

				var vout = (JArray)json.GetValue("vout");
				for (int i = 0; i < vout.Count; i++)
				{
					var jsonOut = (JObject)vout[i];
					var txout = new TxOut();
					tx.Outputs.Add(txout);

					var btc = (decimal)jsonOut.GetValue("value");
					var satoshis = btc * Money.COIN;
					txout.Value = new Money((long)(satoshis));

					var script = (JObject)jsonOut.GetValue("scriptPubKey");
					txout.ScriptPubKey = new Script(Encoders.Hex.DecodeData((string)script.GetValue("hex")));
				}
			}
		}

		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			// a large 4-byte int at any alignment.
			var messageStart = new byte[4];
			messageStart[0] = 0x70;
			messageStart[1] = 0x35;
			messageStart[2] = 0x22;
			messageStart[3] = 0x05;
			var magic = BitConverter.ToUInt32(messageStart, 0); //0x5223570;

			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"),
				PowLimit = new Target(new uint256("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = 105,
				ConsensusFactory = StratisConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 63 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 125 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 63 + 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, "bc")
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, "bc")
			.SetMagic(magic)
			.SetPort(16178)
			.SetRPCPort(16174)
			.SetName("StratisMain")
			.AddDNSSeeds(new[]
			{
					new DNSSeedData("seednode1.stratisplatform.com", "seednode1.stratisplatform.com"),
					new DNSSeedData("seednode2.stratis.cloud", "seednode2.stratis.cloud"),
					new DNSSeedData("seednode3.stratisplatform.com", "seednode3.stratisplatform.com"),
					new DNSSeedData("seednode4.stratis.cloud", "seednode4.stratis.cloud")
			})
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba265b88ba557ffff0f1eddf21b000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000");

			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			// a large 4-byte int at any alignment.
			var messageStart = new byte[4];
			messageStart = new byte[4];
			messageStart[0] = 0x71;
			messageStart[1] = 0x31;
			messageStart[2] = 0x21;
			messageStart[3] = 0x11;
			var magic = BitConverter.ToUInt32(messageStart, 0); //0x5223570; 
			builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				PowLimit = new Target(uint256.Parse("0000ffff00000000000000000000000000000000000000000000000000000000")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = 105,				
				ConsensusFactory = StratisConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 65 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 65 + 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetMagic(magic)
			.SetPort(26178)
			.SetRPCPort(26174)
			.SetName("StratisTest")
			.AddDNSSeeds(new[]
			{
					new DNSSeedData("testnet1.stratisplatform.com", "testnet1.stratisplatform.com"),
					new DNSSeedData("testnet2.stratisplatform.com", "testnet2.stratisplatform.com"),
					new DNSSeedData("testnet3.stratisplatform.com", "testnet3.stratisplatform.com"),
					new DNSSeedData("testnet4.stratisplatform.com", "testnet4.stratisplatform.com")
			})
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba265db3e0b59ffff001fdf2225000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000");

			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			NetworkBuilder builder = new NetworkBuilder();
			// a large 4-byte int at any alignment.
			var messageStart = new byte[4];
			messageStart = new byte[4];
			messageStart[0] = 0xcd;
			messageStart[1] = 0xf2;
			messageStart[2] = 0xc0;
			messageStart[3] = 0xef;
			var magic = BitConverter.ToUInt32(messageStart, 0);
			builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				PowLimit = new Target(uint256.Parse("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(10 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				CoinType = 105,
				ConsensusFactory = StratisConsensusFactory.Instance
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 65 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 196 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 65 + 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetMagic(magic)
			.SetPort(18444)
			.SetRPCPort(18442)
			.SetName("StratisRegTest")
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba2651b811a59ffff7f20df2225000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000");

			return builder;			
		}
	}
}
