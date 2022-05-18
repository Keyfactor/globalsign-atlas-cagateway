using CSS.PKI;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy
{
	public class ValidationPolicyResponse
	{
		[JsonProperty("validity")]
		public ValidityResponse Validity { get; set; }

		[JsonProperty("subject_dn")]
		public SubjectDNResponse SubjectDN { get; set; }

		[JsonProperty("san")]
		public SANResponse San { get; set; }

		[JsonProperty("key_usages")]
		public KeyUsageResponse KeyUsages { get; set; }

		[JsonProperty("extended_key_usages")]
		public EKUResponse EKUs { get; set; }

		[JsonProperty("signature")]
		public SignatureResponse Signature { get; set; }

		[JsonProperty("public_key")]
		public PublicKeyResponse PublicKey { get; set; }

		[JsonProperty("public_key_signature")]
		public string PublicKeySignature { get; set; }
	}

	public class ValidityResponse
	{
		[JsonProperty("secondsmin")]
		public long SecondsMin { get; set; }

		[JsonProperty("secondsmax")]
		public long SecondsMax { get; set; }

		[JsonProperty("not_before_negative_skew")]
		public long NotBeforeNegativeSkew { get; set; }

		[JsonProperty("not_before_positive_skew")]
		public long NotBeforePositiveSkew { get; set; }
	}

	public class SubjectDNResponse
	{
		[JsonProperty("common_name")]
		public SubjectPartResponse CommonName { get; set; }

		[JsonProperty("given_name")]
		public SubjectPartResponse GivenName { get; set; }

		[JsonProperty("surname")]
		public SubjectPartResponse Surname { get; set; }

		[JsonProperty("organization")]
		public SubjectPartResponse Organization { get; set; }

		[JsonProperty("organization_identifier")]
		public SubjectPartResponse OrganizationIdentifier { get; set; }

		[JsonProperty("organizational_unit")]
		public OUResponse OrganizationalUnit { get; set; }

		[JsonProperty("country")]
		public SubjectPartResponse Country { get; set; }

		[JsonProperty("state")]
		public SubjectPartResponse State { get; set; }

		[JsonProperty("locality")]
		public SubjectPartResponse Locality { get; set; }

		[JsonProperty("postal_code")]
		public SubjectPartResponse PostalCode { get; set; }

		[JsonProperty("street_address")]
		public SubjectPartResponse StreetAddress { get; set; }

		[JsonProperty("email")]
		public SubjectPartResponse Email { get; set; }

		[JsonProperty("jurisdiction_of_incorporation_locality_name")]
		public SubjectPartResponse IncorporationLocality { get; set; }

		[JsonProperty("jurisdiction_of_incorporation_state_or_province_name")]
		public SubjectPartResponse IncorporationState { get; set; }

		[JsonProperty("jurisdiction_of_incorporation_country_name")]
		public SubjectPartResponse IncorporationCountry { get; set; }

		[JsonProperty("business_category")]
		public SubjectPartResponse BusinessCategory { get; set; }

		[JsonProperty("serial_number")]
		public SubjectPartResponse SerialNumber { get; set; }
	}

	public class SubjectPartResponse
	{
		[JsonProperty("presence")]
		public string Presence { get; set; }

		[JsonProperty("format")]
		public string Format { get; set; }

		[JsonProperty("ignore_empty")]
		public bool IgnoreEmpty { get; set; }
	}

	public class OUResponse
	{
		[JsonProperty("static")]
		public bool Static { get; set; }

		[JsonProperty("list")]
		public List<string> List { get; set; }

		[JsonProperty("mincount")]
		public int MinCount { get; set; }

		[JsonProperty("maxcount")]
		public int MaxCount { get; set; }

		[JsonProperty("ignore_empty")]
		public bool IgnoreEmpty { get; set; }
	}

	public class SANResponse
	{
		[JsonProperty("critical")]
		public bool Critical { get; set; }

		[JsonProperty("dns_names")]
		public ListTypeResponse DNSNames { get; set; }

		[JsonProperty("emails")]
		public ListTypeResponse Emails { get; set; }

		[JsonProperty("ip_addresses")]
		public ListTypeResponse IPAddresses { get; set; }

		[JsonProperty("uris")]
		public ListTypeResponse URIs { get; set; }
	}

	public class ListTypeResponse
	{
		[JsonProperty("static")]
		public bool Static { get; set; }

		[JsonProperty("list")]
		public List<string> List { get; set; }

		[JsonProperty("mincount")]
		public int MinCount { get; set; }

		[JsonProperty("maxcount")]
		public int MaxCount { get; set; }
	}

	public class KeyUsageResponse
	{
		[JsonProperty("digital_signature")]
		public string DigitalSignature { get; set; }

		[JsonProperty("content_commitment")]
		public string ContentCommitment { get; set; }

		[JsonProperty("key_encipherment")]
		public string KeyEncipherment { get; set; }

		[JsonProperty("data_encipherment")]
		public string DataEncipherment { get; set; }

		[JsonProperty("key_agreement")]
		public string KeyAgreement { get; set; }

		[JsonProperty("key_certificate_sign")]
		public string KeyCertificateSign { get; set; }

		[JsonProperty("crl_sign")]
		public string CRLSign { get; set; }

		[JsonProperty("encipher_only")]
		public string EncipherOnly { get; set; }

		[JsonProperty("decipher_only")]
		public string DecipherOnly { get; set; }
	}

	public class EKUResponse
	{
		[JsonProperty("critical")]
		public bool Critical { get; set; }

		[JsonProperty("ekus")]
		public ListTypeResponse EKUs { get; set; }
	}

	public class SignatureResponse
	{
		[JsonProperty("algorithm")]
		public AlgorithmResponse Algorithm { get; set; }

		[JsonProperty("hash_algorithm")]
		public AlgorithmResponse HashAlgorithm { get; set; }
	}

	public class AlgorithmResponse
	{
		[JsonProperty("presence")]
		public string Presence { get; set; }

		[JsonProperty("list")]
		public List<string> List { get; set; }
	}

	public class PublicKeyResponse
	{
		[JsonProperty("key_type")]
		public string KeyType { get; set; }

		[JsonProperty("allowed_lengths")]
		public List<int> AllowedLengths { get; set; }

		[JsonProperty("key_format")]
		public string KeyFormat { get; set; }
	}
}