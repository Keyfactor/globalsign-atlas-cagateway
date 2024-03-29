﻿using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Configuration;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.AnyGateway.Models.Configuration;
using CAProxy.Common;

using CSS.PKI;
using CSS.PKI.PEM;

using Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy;
using Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.Client;

using Org.BouncyCastle.Asn1.X509;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using AtlasConstants = Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.Constants;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas
{
	public class GlobalSignAtlasCAConnector : BaseCAConnector, ICAConnectorConfigInfoProvider
	{
		#region Fields and Constructors

		/// <summary>
		/// Provides configuration information for the <see cref="GlobalSignAtlasCAConnector"/>
		/// </summary>
		private ICAConnectorConfigProvider ConfigProvider { get; set; }

		#endregion Fields and Constructors

		#region ICAConnector Methods

		/// <summary>
		/// Initialize the <see cref="GlobalSignAtlasCAConnector"/>
		/// </summary>
		/// <param name="configProvider">The config provider contains information required to connect to the CA.</param>
		public override void Initialize(ICAConnectorConfigProvider configProvider)
		{
			ConfigProvider = configProvider;
		}

		[Obsolete]
		public override EnrollmentResult Enroll(string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Enrolls for a certificate through the GlobalSign Atlas API.
		/// </summary>
		/// <param name="certificateDataReader">Reads certificate data from the database.</param>
		/// <param name="csr">The certificate request CSR in PEM format.</param>
		/// <param name="subject">The subject of the certificate request.</param>
		/// <param name="san">Any SANs added to the request.</param>
		/// <param name="productInfo">Information about the CA product type.</param>
		/// <param name="requestFormat">The format of the request.</param>
		/// <param name="enrollmentType">The type of the enrollment, i.e. new, renew, or reissue.</param>
		/// <returns></returns>
		public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr, string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo, PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
		{
			Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
			AtlasClient client = CreateClient(connectionInfo);
			Enroll enrollData = new Enroll();
			csr = PemUtilities.DERToPEM(Convert.FromBase64String(csr), PemUtilities.PemObjectType.CertRequest);
			enrollData.CSR = csr;
			var validation = client.GetValidationPolicy();
			var days = (productInfo.ProductParameters.ContainsKey("Lifetime")) ? int.Parse(productInfo.ProductParameters["Lifetime"]) : 365;

			Logger.Trace($"Verifying validity period:");
			long validitySeconds = days * 24 * 60 * 60;
			if (validitySeconds > validation.Validity.SecondsMax || validitySeconds < validation.Validity.SecondsMin)
			{
				int minDays = Convert.ToInt32(Math.Ceiling(validation.Validity.SecondsMin / 60.0 / 60.0 / 24.0));
				int maxDays = Convert.ToInt32(Math.Floor(validation.Validity.SecondsMax / 60.0 / 60.0 / 24.0));
				string errMsg = $"Invalid validity period. Valid period is between {minDays} and {maxDays} days.";
				Logger.Error(errMsg);
				throw new Exception(errMsg);
			}

			enrollData.Validity.NotBefore = DateTime.UtcNow;
			enrollData.Validity.NotAfter = enrollData.Validity.NotBefore.AddDays(days);

			X509Name subjectParsed = new X509Name(subject);
			// Only populate subject fields that are required or optional
			string subjectField, validationPresence;

			subjectField = subjectParsed.GetValueList(X509Name.CN).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.CommonName.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"Common Name is required");
					throw new Exception("Common Name is required");
				}
				enrollData.SubjectDN.CommonName = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow Common Name, skipping");
			}

			subjectField = subjectParsed.GetValueList(X509Name.C).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Country.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"Country is required");
					throw new Exception("Country is required");
				}
				enrollData.SubjectDN.Country = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow Country, skipping");
			}

			subjectField = subjectParsed.GetValueList(X509Name.E).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Email.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"Email is required");
					throw new Exception("Email is required");
				}
				enrollData.SubjectDN.Email = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow Email, skipping");
			}

			subjectField = subjectParsed.GetValueList(X509Name.L).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Locality.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"Locality is required");
					throw new Exception("Locality is required");
				}
				enrollData.SubjectDN.Locality = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow Locality, skipping");
			}

			subjectField = subjectParsed.GetValueList(X509Name.O).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.Organization.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"Organization is required");
					throw new Exception("Organization is required");
				}
				enrollData.SubjectDN.Organization = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow Organization, skipping");
			}

			subjectField = subjectParsed.GetValueList(X509Name.ST).Cast<string>().LastOrDefault();
			validationPresence = validation.SubjectDN.State.Presence;
			if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) || validationPresence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				if (validationPresence.Equals("required", StringComparison.OrdinalIgnoreCase) && subjectField == null)
				{
					Logger.Error($"State is required");
					throw new Exception("State is required");
				}
				enrollData.SubjectDN.State = subjectField;
			}
			else if (subjectField != null)
			{
				Logger.Warn($"Validation Policy does not allow State, skipping");
			}

			var sanDict = new Dictionary<string, string[]>(san, StringComparer.OrdinalIgnoreCase);
			if (!validation.San.DNSNames.Static)
			{
				if (sanDict.ContainsKey("dns"))
					foreach (var dnsSan in sanDict["dns"])
						enrollData.SANs.DNSList.Add(dnsSan);
			}
			else if (sanDict.ContainsKey("dns"))
			{
				Logger.Warn($"Validation Policy does not allow DNS SANs, skipping");
			}

			if (!validation.San.IPAddresses.Static)
			{
				if (sanDict.ContainsKey("ipaddress"))
					foreach (var ipSan in sanDict["ipaddress"])
						enrollData.SANs.IPList.Add(ipSan);
			}
			else if (sanDict.ContainsKey("ipaddress"))
			{
				Logger.Warn($"Validation Policy does not allow IP address SANs, skipping");
			}

			if (!validation.San.Emails.Static)
			{
				if (sanDict.ContainsKey("email"))
					foreach (var emailSan in sanDict["email"])
						enrollData.SANs.EmailList.Add(emailSan);
			}
			else if (sanDict.ContainsKey("email"))
			{
				Logger.Warn($"Validation Policy does not allow email SANs, skipping");
			}

			string keyUsage = ((productInfo.ProductParameters.ContainsKey("KeyUsage")) ? productInfo.ProductParameters["KeyUsage"] : "").ToLower();
			if (!validation.EKUs.EKUs.Static)
			{
				if (string.IsNullOrEmpty(keyUsage))
				{
					keyUsage = "clientserver";
				}
				if (keyUsage.Contains("server"))
				{
					enrollData.EKUList.Add("1.3.6.1.5.5.7.3.1");
				}
				if (keyUsage.Contains("client"))
				{
					enrollData.EKUList.Add("1.3.6.1.5.5.7.3.2");
				}
			}
			else if (!string.IsNullOrEmpty(keyUsage))
			{
				Logger.Warn($"Validation Policy does not allow EKUs, skipping");
			}

			if (validation.Signature.HashAlgorithm.Presence.Equals("required", StringComparison.OrdinalIgnoreCase) || validation.Signature.HashAlgorithm.Presence.Equals("optional", StringComparison.OrdinalIgnoreCase))
			{
				enrollData.Sig.HashAlgorithm = "SHA-256";
			}

			int pickupDelay = connectionInfo.ContainsKey(AtlasConstants.PICKUP_DELAY) ? (int)connectionInfo[AtlasConstants.PICKUP_DELAY] : 5;
			int pickupRetries = connectionInfo.ContainsKey(AtlasConstants.PICKUP_RETRIES) ? (int)connectionInfo[AtlasConstants.PICKUP_RETRIES] : 5;

			var response = client.RequestNewCertificate(enrollData, pickupDelay, pickupRetries);
			if (response.Status != PKIConstants.Microsoft.RequestDisposition.ISSUED)
			{
				throw new Exception($"Certificate was not issued. Status: {response.StatusMessage}");
			}
			EnrollmentResult result = new EnrollmentResult();
			result.CARequestID = response.SerialNumber;
			result.Status = (int)response.Status;
			result.StatusMessage = string.Format(response.StatusMessage, subject);
			result.Certificate = Convert.ToBase64String(PemUtilities.PEMToDER(response.Cert));
			return result;
		}

		/// <summary>
		/// Returns a single certificate record by its serial number.
		/// </summary>
		/// <param name="caRequestID">The CA request ID for the certificate.</param>
		/// <returns></returns>
		public override CAConnectorCertificate GetSingleRecord(string caRequestID)
		{
			Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
			AtlasClient client = CreateClient(connectionInfo);
			var certResponse = client.GetCertificate(caRequestID);

			return new CAConnectorCertificate
			{
				CARequestID = caRequestID,
				Certificate = certResponse.Certificate,
				Status = certResponse.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? 20 :
							certResponse.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? 21 : 8,
			};
		}

		/// <summary>
		/// Attempts to reach the CA over the network.
		/// </summary>
		public override void Ping()
		{
			try
			{
				Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
				AtlasClient client = CreateClient(connectionInfo);
				client.GetValidationPolicy();
			}
			catch (Exception e)
			{
				Logger.Error($"Error attempting to contact GlobalSign Atlas: {e.Message}");
				throw new Exception($"Error attempting to contact GlobalSign Atlas: {e.Message}", e);
			}
		}

		/// <summary>
		/// Revokes a certificate by its serial number.
		/// </summary>
		/// <param name="caRequestID">The CA request ID.</param>
		/// <param name="hexSerialNumber">The hex-encoded serial number.</param>
		/// <param name="revocationReason">The revocation reason.</param>
		/// <returns></returns>
		public override int Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
		{
			Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
			AtlasClient client = CreateClient(connectionInfo);
			client.RevokeCertificate(caRequestID);

			var certResponse = client.GetCertificate(caRequestID);
			return (certResponse.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? 20 :
						certResponse.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? 21 : 8);
		}

		[Obsolete]
		public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CertificateRecord> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken, string logicalName)
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Synchronizes the gateway with the external CA
		/// </summary>
		/// <param name="certificateDataReader">Provides information about the gateway's certificate database.</param>
		/// <param name="blockingBuffer">Buffer into which certificates are places from the CA.</param>
		/// <param name="certificateAuthoritySyncInfo">Information about the last CA sync.</param>
		/// <param name="cancelToken">The cancellation token.</param>
		public override void Synchronize(ICertificateDataReader certificateDataReader, BlockingCollection<CAConnectorCertificate> blockingBuffer, CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken)
		{
			Dictionary<string, object> connectionInfo = ConfigProvider.CAConnectionData;
			AtlasClient client = CreateClient(connectionInfo);
			var certs = client.GetAllCertificates(certificateAuthoritySyncInfo.LastIncrementalSync, certificateAuthoritySyncInfo.DoFullSync);

			foreach (var cert in certs)
			{
				var connectorCert = new CAConnectorCertificate()
				{
					CARequestID = cert.Status.SerialNumber,
					Certificate = cert.Cert.Certificate,
					Status = cert.Cert.Status.Equals("issued", StringComparison.OrdinalIgnoreCase) ? 20 :
							cert.Cert.Status.Equals("revoked", StringComparison.OrdinalIgnoreCase) ? 21 : 8,
				};
				blockingBuffer.Add(connectorCert);
			}
		}

		/// <summary>
		/// Validates that the CA connection info is correct.
		/// </summary>
		/// <param name="connectionInfo">The information used to connect to the CA.</param>
		public override void ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
		{
			Logger.Trace("Validating CA Connection info");
			List<string> errors = new List<string>();
			Logger.Trace("Checking for API Key/Secret");
			string apiKey = connectionInfo.ContainsKey(Constants.API_KEY) ? (string)connectionInfo[Constants.API_KEY] : string.Empty;
			if (string.IsNullOrWhiteSpace(apiKey))
			{
				errors.Add("The API Key is required");
			}
			string apiSecret = connectionInfo.ContainsKey(Constants.API_SECRET) ? (string)connectionInfo[Constants.API_SECRET] : string.Empty;
			if (string.IsNullOrWhiteSpace(apiSecret))
			{
				errors.Add("The API Secret is required");
			}

			Logger.Trace("Checking for sync start date");
			string syncStartString = connectionInfo.ContainsKey(AtlasConstants.SYNC_START_DATE) ? (string)connectionInfo[AtlasConstants.SYNC_START_DATE] : string.Empty;
			if (string.IsNullOrWhiteSpace(syncStartString))
			{
				errors.Add("The sync start date is required");
			}
			else
			{
				if (!DateTime.TryParse(syncStartString, out _))
				{
					errors.Add("Sync start date could not be parsed");
				}
			}

			Logger.Trace("Checking for client certificate data");
			Dictionary<string, object> clientCert;
			X509Certificate2 authCert = null;
			if (!connectionInfo.ContainsKey(Constants.CLIENT_CERTIFICATE))
			{
				errors.Add("The client certificate is required");
			}
			else
			{
				clientCert = (Dictionary<string, object>)connectionInfo[Constants.CLIENT_CERTIFICATE];
				if (!clientCert.ContainsKey(Constants.STORE_LOCATION)
					|| !clientCert.ContainsKey(Constants.STORE_NAME)
					|| !clientCert.ContainsKey(Constants.THUMBPRINT))
				{
					errors.Add("The store location, store name, and thumbprint of the client certificate are required.");
				}
				else
				{
					Logger.Trace("Checking for the auth certificate");
					StoreLocation storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), (string)clientCert[Constants.STORE_LOCATION]);
					GatewayCertificate finder = new GatewayCertificate();
					try
					{
						authCert = finder.FindGatewayCertificate((string)clientCert[Constants.STORE_NAME], storeLocation, (string)clientCert[Constants.THUMBPRINT]);
					}
					catch (Exception e)
					{
						errors.Add(e.Message);
					}

					Logger.Trace("Checking for private key permissions");
					try
					{
						_ = authCert.GetRSAPrivateKey();
						_ = authCert.GetDSAPrivateKey();
						_ = authCert.GetECDsaPrivateKey();
					}
					catch
					{
						errors.Add("The service user cannot access the authentication certificate's private key");
					}
				}
			}

			if (errors.Any())
			{
				throw new Exception(string.Join("\n", errors));
			}
			Logger.Trace("CA Connection info validation complete");
		}

		/// <summary>
		/// Validates that the product information for the CA is correct
		/// </summary>
		/// <param name="productInfo">The product information.</param>
		/// <param name="connectionInfo">The CA connection information.</param>
		public override void ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
		{
			//Do nothing
		}

		#endregion ICAConnector Methods

		#region ICAConnectorConfigInfoProvider Methods

		/// <summary>
		/// Returns the default CA connector section of the config file.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, object> GetDefaultCAConnectorConfig()
		{
			Dictionary<string, string> clientCert = new Dictionary<string, string>()
			{
				{ Constants.STORE_NAME, "" },
				{ Constants.STORE_LOCATION, "" },
				{ Constants.THUMBPRINT, "" }
			};
			return new Dictionary<string, object>()
			{
				{ Constants.API_KEY, "" },
				{ Constants.API_SECRET, "" },
				{ Constants.CLIENT_CERTIFICATE, clientCert },
				{ Constants.SYNC_START_DATE, "2022-01-01" },
				{ Constants.PICKUP_DELAY, 5 },
				{ Constants.PICKUP_RETRIES, 5 }
			};
		}

		/// <summary>
		/// Gets teh default comment on the default product type.
		/// </summary>
		/// <returns></returns>
		public string GetProductIDComment()
		{
			return "";
		}

		/// <summary>
		/// Gets annotations for the CA connector properties.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
		{
			return new Dictionary<string, PropertyConfigInfo>();
		}

		/// <summary>
		/// Gets annotations for the template mapping parameters
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
		{
			throw new NotImplementedException();
		}

		/// <summary>
		/// Gets default template map parameters for GlobalSign Atlas product types.
		/// </summary>
		/// <returns></returns>
		public Dictionary<string, string> GetDefaultTemplateParametersConfig()
		{
			throw new NotImplementedException();
		}

		#endregion ICAConnectorConfigInfoProvider Methods

		#region Helpers

		private AtlasClient CreateClient(Dictionary<string, object> connectionInfo)
		{
			string apiKey = connectionInfo.ContainsKey(AtlasConstants.API_KEY) ? (string)connectionInfo[AtlasConstants.API_KEY] : string.Empty;
			string apiSecret = connectionInfo.ContainsKey(AtlasConstants.API_SECRET) ? (string)connectionInfo[AtlasConstants.API_SECRET] : string.Empty;

			if (string.IsNullOrEmpty(apiKey) || string.IsNullOrEmpty(apiSecret))
			{
				Logger.Error($"Unable to create Atlas client, missing either API key or secret");
				throw new Exception("Unable to create Atlas client");
			}

			Dictionary<string, object> clientCertificate = (Dictionary<string, object>)connectionInfo[AtlasConstants.CLIENT_CERTIFICATE];

			Logger.Trace("Checking for authentication certificate.");
			StoreLocation storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), (string)clientCertificate[AtlasConstants.STORE_LOCATION]);
			GatewayCertificate finder = new GatewayCertificate();
			X509Certificate2 authCert = finder.FindGatewayCertificate((string)clientCertificate[AtlasConstants.STORE_NAME], storeLocation, (string)clientCertificate[AtlasConstants.THUMBPRINT]);

			if (authCert == null)
			{
				Logger.Error($"Unable to create Atlas client, cannot find client certificate");
				throw new Exception("Unable to create Atlas client");
			}

			string syncStartString = connectionInfo.ContainsKey(AtlasConstants.SYNC_START_DATE) ? (string)connectionInfo[AtlasConstants.SYNC_START_DATE] : string.Empty;
			if (string.IsNullOrEmpty(syncStartString))
			{
				Logger.Error($"Sync start date is required");
				throw new Exception("Unable to create Atlas client");
			}
			DateTime syncStart;
			if (!DateTime.TryParse(syncStartString, out syncStart))
			{
				Logger.Error($"Unable to parse sync start time");
				throw new Exception("Unable to create Atlas client");
			}
			AtlasClient client = new AtlasClient(apiKey, apiSecret, authCert, syncStart);
			return client;
		}

		private static string ParseSubject(string subject, string rdn)
		{
			string escapedSubject = subject.Replace("\\,", "|");
			string rdnString = escapedSubject.Split(',').ToList().Where(x => x.Contains(rdn)).FirstOrDefault();

			if (!string.IsNullOrEmpty(rdnString))
			{
				return rdnString.Replace(rdn, "").Replace("|", ",").Trim();
			}
			else
			{
				throw new Exception($"The request is missing a {rdn} value");
			}
		}

		#endregion Helpers
	}
}