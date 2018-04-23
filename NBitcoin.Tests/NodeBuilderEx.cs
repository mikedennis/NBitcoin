using System.Runtime.CompilerServices;

namespace NBitcoin.Tests
{
	public class NodeBuilderEx
	{
		public static NodeBuilder Create([CallerMemberName] string caller = null)
		{
			//Altcoins.Litecoin.EnsureRegistered();
			//return NodeBuilder.Create(NodeDownloadData.Litecoin.v0_15_1, Altcoins.Litecoin.Regtest, caller);

			//Altcoins.BCash.EnsureRegistered();
			//return NodeBuilder.Create(NodeDownloadData.BCash.v0_16_2, Altcoins.BCash.Regtest, caller);

			//Altcoins.Dogecoin.EnsureRegistered();
			//var builder = NodeBuilder.Create(NodeDownloadData.Dogecoin.v1_10_0, Altcoins.Dogecoin.Regtest, caller);
			//builder.SupportCookieFile = false;
			//return builder;

			//Altcoins.Dash.EnsureRegistered();
			//var builder = NodeBuilder.Create(NodeDownloadData.Dash.v0_12_2, Altcoins.Dash.Regtest, caller);
			//return builder;

			Altcoins.Stratis.EnsureRegistered();
			var builder = NodeBuilder.Create(NodeDownloadData.Stratis.v1_0_2_alpha, Altcoins.Stratis.Regtest, caller);
			builder.SupportCookieFile = false;
			return builder;

			//return NodeBuilder.Create(NodeDownloadData.Bitcoin.v0_16_0, Network.RegTest, caller);
		}
	}
}
