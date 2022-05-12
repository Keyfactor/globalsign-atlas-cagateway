using Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy;
using Keyfactor.Logging;

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

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.Client
{
	public class AtlasClient
	{
		private static ILogger Logger => LogHandler.GetClassLogger<AtlasClient>();
		private string ApiKey { get; set; }
		private string ApiSecret { get; set; }
		private X509Certificate2 AuthCert { get; set; }
		private string BaseUrl { get; set; }

		private string Token { get; set; }
		private DateTime TokenTime { get; set; }

		private DateTime SyncStart { get; set; }

		private class AtlasResponse
		{
			public bool Success { get; set; }
			public string Response { get; set; }

			public AtlasResponse()
			{
				Success = true;
				Response = "";
			}
		}

		public AtlasClient(string apiKey, string apiSecret, X509Certificate2 authCert, DateTime syncStart)
			: this(apiKey, apiSecret, authCert, syncStart, "https://emea.api.hvca.globalsign.com:8443/v2/")
		{
		}

		public AtlasClient(string apiKey, string apiSecret, X509Certificate2 authCert, DateTime syncStart, string baseUrl)
		{
			ApiKey = apiKey;
			ApiSecret = apiSecret;
			AuthCert = authCert;
			BaseUrl = baseUrl;
			SyncStart = syncStart;
		}

		private void RefreshApiToken()
		{
			Logger.MethodEntry(LogLevel.Debug);
			try
			{
				string targetUri = BaseUrl + "login/";
				HttpWebRequest request = (HttpWebRequest)WebRequest.Create(targetUri);
				request.Method = "POST";
				request.ContentType = "application/json;charset=utf-8";
				request.Headers["X-SSL-Client-Serial"] = AuthCert.SerialNumber;
				request.ClientCertificates.Add(AuthCert);
				var loginReq = new LoginRequest()
				{
					Key = ApiKey,
					Secret = ApiSecret
				};
				string postBody = JsonConvert.SerializeObject(loginReq, Formatting.None, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
				byte[] postBytes = Encoding.UTF8.GetBytes(postBody);

				request.ContentLength = postBytes.Length;
				Stream requestStream = request.GetRequestStream();
				requestStream.Write(postBytes, 0, postBytes.Length);
				requestStream.Close();

				LoginResponse apiResponse = new LoginResponse();
				TokenTime = DateTime.UtcNow;

				Logger.LogTrace($"Atlas Request: POST {targetUri}");
				using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
				{
					apiResponse = JsonConvert.DeserializeObject<LoginResponse>(new StreamReader(response.GetResponseStream()).ReadToEnd());
				}
				Token = apiResponse.Token;
			}
			catch (Exception ex)
			{
				Logger.LogError($"Atlas response error: {ex.Message}");
				throw new Exception($"Unable to establish connection to Atlas web service: {ex.Message}", ex);
			}
		}

		public EnrollResponse RequestNewCertificate(Enroll request)
		{
			EnrollResponse enrollResponse = new EnrollResponse();
			string certUrl = null;
			try
			{
				string targetUri = BaseUrl + "certificates/";
				string method = "POST";

				Logger.LogTrace($"Requesting new certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(AuthCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + Token);

				byte[] postBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(request));
				apiRequest.ContentLength = postBytes.Length;
				Stream requestStream = apiRequest.GetRequestStream();
				requestStream.Write(postBytes, 0, postBytes.Length);
				requestStream.Close();

				Logger.LogTrace($"Atlas Request: POST {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.Created)
					{
						certUrl = apiResponse.Headers["Location"];
						enrollResponse.SerialNumber = certUrl.Substring(certUrl.LastIndexOf('/') + 1);
					}
					else
					{
						throw new Exception($"Unable to enroll for certificate, status code: {apiResponse.StatusCode}");
					}
				}

				targetUri = BaseUrl + "certificates/" + enrollResponse.SerialNumber;
				method = "GET";

				Logger.LogTrace($"Enrollment successful, retrieving new certificate");
				apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(AuthCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + Token);

				Logger.LogTrace($"Atlas Request: GET {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.OK)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());
						enrollResponse.Status = CSS.PKI.PKIConstants.Microsoft.RequestDisposition.ISSUED;
						enrollResponse.Cert = certResponse.Certificate;
						enrollResponse.StatusMessage = "Successfully enrolled for certificate {0}";
					}
					else if (apiResponse.StatusCode == HttpStatusCode.Accepted)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

						enrollResponse.Status = CSS.PKI.PKIConstants.Microsoft.RequestDisposition.IN_PROCESS;
						enrollResponse.StatusMessage = certResponse.Description;
					}
					else
					{
						throw new Exception($"Unable to enroll for certificate, status code: {apiResponse.StatusCode}");
					}
				}
				return enrollResponse;
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var stream = wex.Response.GetResponseStream())
					using (var reader = new StreamReader(stream))
					{
						string errorString = reader.ReadToEnd();
						Logger.LogError($"Atlas CA has returned an error from enrolling: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
						throw new Exception(errorString, wex);
					}
				}
				else
				{
					Logger.LogError($"Error enrolling for cert", wex);
					throw new Exception($"Error enrolling for cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError("Error enrolling for cert", ex);
				throw new Exception($"Error enrolling for cert", ex);
			}
		}

		public CertificateResponse GetCertificate(string caRequestID)
		{
			try
			{
				string targetUri = BaseUrl + "certificates/" + caRequestID;
				string method = "GET";

				Logger.LogTrace($"Retrieving certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(AuthCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + Token);

				Logger.LogTrace($"Atlas Request: GET {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.OK)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());
						return certResponse;
					}
					else if (apiResponse.StatusCode == HttpStatusCode.Accepted)
					{
						CertificateResponse certResponse = JsonConvert.DeserializeObject<CertificateResponse>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

						return certResponse;
					}
					else
					{
						throw new Exception($"Unable to retrieve certificate, status code: {apiResponse.StatusCode}");
					}
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var stream = wex.Response.GetResponseStream())
					using (var reader = new StreamReader(stream))
					{
						string errorString = reader.ReadToEnd();
						Logger.LogError($"Atlas CA has returned an error from retrieving certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
						throw new Exception(errorString, wex);
					}
				}
				else
				{
					Logger.LogError($"Error retrieving cert", wex);
					throw new Exception($"Error retrieving cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError("Error retrieving cert", ex);
				throw new Exception($"Error retrieving cert", ex);
			}
		}

		public void RevokeCertificate(string caRequestID)
		{
			try
			{
				string targetUri = BaseUrl + "certificates/" + caRequestID;
				string method = "DELETE";

				Logger.LogTrace($"Attempting to revoke certificate");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(AuthCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + Token);

				Logger.LogTrace($"Atlas Request: DELETE {targetUri}");
				using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
				{
					Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
					if (apiResponse.StatusCode == HttpStatusCode.NoContent)
					{
						Logger.LogTrace($"Certificate successfully revoked");
					}
					else
					{
						throw new Exception($"Unable to revoke certificate, status code: {apiResponse.StatusCode}");
					}
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var stream = wex.Response.GetResponseStream())
					using (var reader = new StreamReader(stream))
					{
						string errorString = reader.ReadToEnd();
						Logger.LogError($"Atlas CA has returned an error from revoking certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
						throw new Exception(errorString, wex);
					}
				}
				else
				{
					Logger.LogError($"Error revoking cert", wex);
					throw new Exception($"Error revoking cert", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError("Error revoking cert", ex);
				throw new Exception($"Error revoking cert", ex);
			}
		}

		public void GetValidationPolicy()
		{
			try
			{
				string targetUri = BaseUrl + "validationpolicy/";
				string method = "GET";

				Logger.LogTrace($"Retrieving validation policy");
				HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
				apiRequest.Method = method;
				apiRequest.ContentType = "application/json;charset=utf-8";
				if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
				{
					RefreshApiToken();
				}
				apiRequest.ClientCertificates.Add(AuthCert);
				apiRequest.Headers.Add("Authorization", "Bearer " + Token);

				Logger.LogTrace($"Atlas Request: GET {targetUri}");
				using (HttpWebResponse response = (HttpWebResponse)apiRequest.GetResponse())
				{
					var fullResponse = new StreamReader(response.GetResponseStream()).ReadToEnd();
				}
			}
			catch (WebException wex)
			{
				if (wex.Response != null)
				{
					using (var stream = wex.Response.GetResponseStream())
					using (var reader = new StreamReader(stream))
					{
						string errorString = reader.ReadToEnd();
						Logger.LogError($"Atlas CA has returned an error from retrieving validation policy: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
						throw new Exception(errorString, wex);
					}
				}
				else
				{
					Logger.LogError($"Error retrieving validation policy", wex);
					throw new Exception($"Error retrieving validation policy", wex);
				}
			}
			catch (Exception ex)
			{
				Logger.LogError("Error retrieving validation policy", ex);
				throw new Exception($"Error retrieving validation policy", ex);
			}
		}

		public List<CertificateDetailsResponse> GetAllCertificates(DateTime? lastIncrementalSync, bool doFullSync)
		{
			if (!lastIncrementalSync.HasValue)
			{
				lastIncrementalSync = SyncStart;
			}
			DateTime startTime = doFullSync ? SyncStart : (lastIncrementalSync.Value);
			DateTime endTime = DateTime.UtcNow;
			long startTimeTicks = ((DateTimeOffset)startTime).ToUnixTimeSeconds();
			long endTimeTicks = ((DateTimeOffset)endTime).ToUnixTimeSeconds();

			List<CertificateDetailsResponse> certs = new List<CertificateDetailsResponse>();

			for (long i = startTimeTicks; i <= endTimeTicks; i += 1728000) // Sync 20 days at a time
			{
				int pagenum = 1;
				bool morePages = false;
				long toTicks = i + 1728000;
				if (toTicks > endTimeTicks)
				{
					toTicks = endTimeTicks;
				}
				do
				{
					morePages = false;
					string targetUri = BaseUrl + "stats/issued?page=" + pagenum + "&from=" + i + "&to=" + toTicks;
					string method = "GET";

					Logger.LogTrace($"Retrieving certificate list");
					HttpWebRequest apiRequest = (HttpWebRequest)WebRequest.Create(targetUri);
					apiRequest.Method = method;
					apiRequest.ContentType = "application/json;charset=utf-8";
					if (string.IsNullOrEmpty(Token) || TokenTime.AddMinutes(10) < DateTime.UtcNow)
					{
						RefreshApiToken();
					}
					apiRequest.ClientCertificates.Add(AuthCert);
					apiRequest.Headers.Add("Authorization", "Bearer " + Token);
					List<CertificateStatusResponse> certResponse;
					try
					{
						Logger.LogTrace($"Atlas Request: GET {targetUri}");
						using (HttpWebResponse apiResponse = (HttpWebResponse)apiRequest.GetResponse())
						{
							Logger.LogTrace($"Atlas API returned response {apiResponse.StatusCode}");
							if (apiResponse.StatusCode == HttpStatusCode.OK)
							{
								certResponse = JsonConvert.DeserializeObject<List<CertificateStatusResponse>>(new StreamReader(apiResponse.GetResponseStream()).ReadToEnd());

								var header = apiResponse.Headers["Links"];
								if (header.Contains("next"))
								{
									morePages = true;
									pagenum++;
								}
							}
							else
							{
								throw new Exception($"Unable to retrieve certificate list, status code: {apiResponse.StatusCode}");
							}
						}
					}
					catch (WebException wex)
					{
						if (wex.Response != null)
						{
							using (var stream = wex.Response.GetResponseStream())
							using (var reader = new StreamReader(stream))
							{
								string errorString = reader.ReadToEnd();
								Logger.LogError($"Atlas CA has returned an error from retrieving certificate: '{((HttpWebResponse)wex.Response).StatusCode}: {errorString}");
								throw new Exception(errorString, wex);
							}
						}
						else
						{
							Logger.LogError($"Error retrieving cert", wex);
							throw new Exception($"Error retrieving cert", wex);
						}
					}
					catch (Exception ex)
					{
						Logger.LogError("Error retrieving cert", ex);
						throw new Exception($"Error retrieving cert", ex);
					}
					foreach (var certStatus in certResponse)
					{
						CertificateDetailsResponse details = new CertificateDetailsResponse();
						details.Status = certStatus;
						details.Cert = GetCertificate(certStatus.SerialNumber);
						certs.Add(details);
					}
				} while (morePages);
			}
			return certs;
		}
	}
}