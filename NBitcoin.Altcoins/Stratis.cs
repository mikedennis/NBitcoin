using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace NBitcoin.Altcoins
{
	public class Stratis
	{
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
#pragma warning disable CS0618 // Type or member is obsolete
			public StratisBlock(BlockHeader h) : base(h)
#pragma warning restore CS0618 // Type or member is obsolete
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Stratis.Mainnet.Consensus.ConsensusFactory;
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

		public class StratisConsensusFactory : ConsensusFactory
		{
			public StratisConsensusFactory()
			{
			}

			public override BlockHeader CreateBlockHeader()
			{
#pragma warning disable CS0618 // Type or member is obsolete
				return new BlockHeader();
#pragma warning restore CS0618 // Type or member is obsolete
			}
			public override Block CreateBlock()
			{
#pragma warning disable CS0618 // Type or member is obsolete
				return new StratisBlock(new BlockHeader());
#pragma warning restore CS0618 // Type or member is obsolete
			}
		}

		public static void EnsureRegistered()
		{
			if (_LazyRegistered.IsValueCreated)
				return;
			// This will cause RegisterLazy to evaluate
			new Lazy<object>[] { _LazyRegistered }.Select(o => o.Value != null).ToList();
		}
		static Lazy<object> _LazyRegistered = new Lazy<object>(RegisterLazy, false);

		private static object RegisterLazy()
		{

			// MAINNET

			NetworkBuilder builder = new NetworkBuilder();
			// a large 4-byte int at any alignment.
			var messageStart = new byte[4];
			messageStart[0] = 0x70;
			messageStart[1] = 0x35;
			messageStart[2] = 0x22;
			messageStart[3] = 0x05;
			var magic = BitConverter.ToUInt32(messageStart, 0); //0x5223570;

			_Mainnet = builder.SetConsensus(new Consensus()
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
				HashGenesisBlock = new uint256("0x0000066e91e46e5a264d42c89e1204963b2ee6be230b443e9159020539d972af"),				
				ConsensusFactory = new StratisConsensusFactory()
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
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba265b88ba557ffff0f1eddf21b000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000")
			.BuildAndRegister();
			
			// TESTNET

			messageStart = new byte[4];
			messageStart[0] = 0x71;
			messageStart[1] = 0x31;
			messageStart[2] = 0x21;
			messageStart[3] = 0x11;
			magic = BitConverter.ToUInt32(messageStart, 0); //0x5223570; 
			builder = new NetworkBuilder();
			_Testnet = builder.SetConsensus(new Consensus()
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
				HashGenesisBlock = new uint256("0x00000e246d7b73b88c9ab55f2e5e94d9e22d471def3df5ea448f5576b1d156b9"),				
				ConsensusFactory = new StratisConsensusFactory()
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
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba265db3e0b59ffff001fdf2225000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000")
			.BuildAndRegister();

			// REGTEST

			messageStart = new byte[4];
			messageStart[0] = 0xcd;
			messageStart[1] = 0xf2;
			messageStart[2] = 0xc0;
			messageStart[3] = 0xef;
			magic = BitConverter.ToUInt32(messageStart, 0);
			builder = new NetworkBuilder();
			_Regtest = builder.SetConsensus(new Consensus()
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
				HashGenesisBlock = new uint256("0x93925104d664314f581bc7ecb7b4bad07bcfabd1cfce4256dbd2faddcf53bd1f"),
				ConsensusFactory = new StratisConsensusFactory()
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
			.SetGenesis("01000000000000000000000000000000000000000000000000000000000000000000000018157f44917c2514c1f339346200f8b27d8ffaae9d8205bfae51030bc26ba2651b811a59ffff7f20df2225000101000000b88ba557010000000000000000000000000000000000000000000000000000000000000000ffffffff5d00012a4c58687474703a2f2f7777772e7468656f6e696f6e2e636f6d2f61727469636c652f6f6c796d706963732d686561642d7072696573746573732d736c6974732d7468726f61742d6f6666696369616c2d72696f2d2d3533343636ffffffff010000000000000000000000000000")
			.BuildAndRegister();

			var home = Environment.GetEnvironmentVariable("HOME");
			var localAppData = Environment.GetEnvironmentVariable("APPDATA");

			if (string.IsNullOrEmpty(home) && string.IsNullOrEmpty(localAppData))
				return new object();

			if (!string.IsNullOrEmpty(home))
			{
				var bitcoinFolder = Path.Combine(home, ".stratis");

				var mainnet = Path.Combine(bitcoinFolder, ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Mainnet, mainnet);

				var testnet = Path.Combine(bitcoinFolder, "testnet4", ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Testnet, testnet);

				var regtest = Path.Combine(bitcoinFolder, "regtest", ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Regtest, regtest);
			}
			else if (!string.IsNullOrEmpty(localAppData))
			{
				var bitcoinFolder = Path.Combine(localAppData, "Stratis");

				var mainnet = Path.Combine(bitcoinFolder, ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Mainnet, mainnet);

				var testnet = Path.Combine(bitcoinFolder, "testnet4", ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Testnet, testnet);

				var regtest = Path.Combine(bitcoinFolder, "regtest", ".cookie");
				RPCClient.RegisterDefaultCookiePath(Stratis._Regtest, regtest);
			}
			return new object();
		}

		private static IEnumerable<NetworkAddress> ToSeed(Tuple<byte[], int>[] tuples)
		{
			return tuples
					.Select(t => new NetworkAddress(new IPAddress(t.Item1), t.Item2))
					.ToArray();
		}

		private static Network _Mainnet;
		public static Network Mainnet
		{
			get
			{
				EnsureRegistered();
				return _Mainnet;
			}
		}

		private static Network _Regtest;
		public static Network Regtest
		{
			get
			{
				EnsureRegistered();
				return _Regtest;
			}
		}

		private static Network _Testnet;
		public static Network Testnet
		{
			get
			{
				EnsureRegistered();
				return _Testnet;
			}
		}
	}
}
