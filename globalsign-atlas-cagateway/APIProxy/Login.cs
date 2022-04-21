using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy
{
	public class LoginRequest
	{
		[JsonProperty("api_key")]
		public string Key { get; set; }

		[JsonProperty("api_secret")]
		public string Secret { get; set; }
	}

	public class LoginResponse
	{
		[JsonProperty("access_token")]
		public string Token { get; set; }
	}
}