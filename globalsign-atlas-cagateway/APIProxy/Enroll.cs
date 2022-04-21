using CSS.PKI;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy
{
	public class EnrollRequest : AtlasBaseRequest
	{
		public EnrollRequest()
		{
			this.Resource = "certificates";
			this.Method = "POST";
		}
	}

	public class EnrollResponse
	{
		public string SerialNumber { get; set; }
		public string Cert { get; set; }
		public PKIConstants.Microsoft.RequestDisposition Status { get; set; }
		public string StatusMessage { get; set; }
	}

	public class Enroll
	{
		[JsonProperty("validity")]
		public ValidityDates Validity { get; set; }

		[JsonProperty("subject_dn")]
		public Subject SubjectDN { get; set; }

		[JsonProperty("san")]
		public AlternateNames SANs { get; set; }

		[JsonProperty("extended_key_usages")]
		public string[] EKUs
		{ get { return EKUList.ToArray(); } }

		[JsonIgnore]
		public List<string> EKUList { get; set; }

		[JsonProperty("public_key")]
		public string CSR { get; set; }

		[JsonProperty("signature")]
		public Signature Sig { get; set; }

		public Enroll()
		{
			Validity = new ValidityDates();
			SubjectDN = new Subject();
			SANs = new AlternateNames();
			Sig = new Signature();
			EKUList = new List<string>();
		}
	}

	public class ValidityDates
	{
		[JsonProperty("not_before")]
		public long NotBeforeInt
		{
			get
			{
				return ((DateTimeOffset)NotBefore).ToUnixTimeSeconds();
			}
		}

		[JsonProperty("not_after")]
		public long NotAfterInt
		{
			get
			{
				return ((DateTimeOffset)NotAfter).ToUnixTimeSeconds();
			}
		}

		[JsonIgnore]
		public DateTime NotBefore { get; set; }

		[JsonIgnore]
		public DateTime NotAfter { get; set; }
	}

	public class Subject
	{
		[JsonProperty("common_name")]
		public string CommonName { get; set; }

		[JsonProperty("country")]
		public string Country { get; set; }

		[JsonProperty("state")]
		public string State { get; set; }

		[JsonProperty("locality")]
		public string Locality { get; set; }

		[JsonProperty("organization")]
		public string Organization { get; set; }

		[JsonProperty("email")]
		public string Email { get; set; }
	}

	public class AlternateNames
	{
		[JsonProperty("dns_names")]
		public string[] DNS
		{ get { return DNSList.ToArray(); } }

		[JsonIgnore]
		public List<string> DNSList { get; set; }

		[JsonProperty("emails")]
		public string[] Emails
		{ get { return EmailList.ToArray(); } }

		[JsonIgnore]
		public List<string> EmailList { get; set; }

		[JsonProperty("ip_addresses")]
		public string[] IPs
		{ get { return IPList.ToArray(); } }

		[JsonIgnore]
		public List<string> IPList { get; set; }

		[JsonProperty("uris")]
		public string[] URIs
		{ get { return URIList.ToArray(); } }

		[JsonIgnore]
		public List<string> URIList { get; set; }

		public AlternateNames()
		{
			DNSList = new List<string>();
			EmailList = new List<string>();
			IPList = new List<string>();
			URIList = new List<string>();
		}
	}

	public class Signature
	{
		[JsonProperty("hash_algorithm")]
		public string HashAlgorithm { get; set; }
	}
}