using CAProxy.AnyGateway.Configuration;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace globalsign_atlas_apitestbed
{
	public class Program
	{
		public struct ClientCertificate
		{
			public string StoreName, StoreLocation, Thumbprint;
		}

		public struct Config
		{
			public string ApiKey, ApiSecret, Token;
			public ClientCertificate ClientCert;
		}

		private static Config config = new Config()
		{
			ApiKey = "d7b97d44e5ff331a",
			ApiSecret = "14b4371b28f0e619940aadcef029b1bd2c6e49a6",
			ClientCert = new ClientCertificate()
			{
				StoreName = "My",
				StoreLocation = "LocalMachine",
				Thumbprint = "72ab8ff299cbadcdd6c14a3d737a6b59431682a8"
			},
			Token = ""
		};

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

		public class EnrollRequest
		{
			public string CommonName { get; set; }
			public string CSR { get; set; }
		}

		private static X509Certificate2 AuthCert { get; set; }

		public static void Main(string[] args)
		{
			System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;
			StoreLocation storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), config.ClientCert.StoreLocation);
			GatewayCertificate finder = new GatewayCertificate();
			X509Certificate2 authCert = finder.FindGatewayCertificate(config.ClientCert.StoreName, storeLocation, config.ClientCert.Thumbprint);
			AuthCert = authCert;
			config.Token = GetAccessToken();
			Enroll();
			//Revoke();
			//Inventory();
			System.Net.ServicePointManager.ServerCertificateValidationCallback = null;
		}

		public static string GetAccessToken()
		{
			try
			{
				string targetUri = "https://emea.api.hvca.globalsign.com:8443/v2/login/";
				HttpWebRequest request = (HttpWebRequest)WebRequest.Create(targetUri);
				request.Method = "POST";
				request.ContentType = "application/json;charset=utf-8";
				request.Headers["X-SSL-Client-Serial"] = AuthCert.SerialNumber;
				request.ClientCertificates.Add(AuthCert);
				var req = new LoginRequest()
				{
					Key = config.ApiKey,
					Secret = config.ApiSecret
				};
				string reqParams = JsonConvert.SerializeObject(req, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
				byte[] postBytes = Encoding.UTF8.GetBytes(reqParams);
				request.ContentLength = postBytes.Length;
				Stream requestStream = request.GetRequestStream();
				requestStream.Write(postBytes, 0, postBytes.Length);
				requestStream.Close();

				using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
				{
					var fullResponse = new StreamReader(response.GetResponseStream()).ReadToEnd();
					LoginResponse lResp = JsonConvert.DeserializeObject<LoginResponse>(fullResponse);
					return lResp.Token;
				}
			}
			catch (WebException wex)
			{
				string message = ((HttpWebResponse)wex.Response).StatusDescription;
				throw;
			}
		}

		public static void Enroll()
		{
			string targetUri = "https://emea.api.hvca.globalsign.com:8443/v2/trustchain/";
			HttpWebRequest request = (HttpWebRequest)WebRequest.Create(targetUri);
			request.Method = "GET";
			//request.ContentType = "application/json;charset=utf-8";
			request.ClientCertificates.Add(AuthCert);
			request.Headers.Add("Authorization", "Bearer " + config.Token);

			using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
			{
				var fullResponse = new StreamReader(response.GetResponseStream()).ReadToEnd();
			}
			//string targetUri = "https://emea.api.hvca.globalsign.com:8443/v2/certificates/";
			//HttpWebRequest request = (HttpWebRequest)WebRequest.Create(targetUri);
			//request.Method = "POST";
			//request.ContentType = "application/json;charset=utf-8";
			//request.ClientCertificates.Add(AuthCert);
			//request.Headers.Add("Authorization", "Bearer " + config.Token);
		}
	}
}