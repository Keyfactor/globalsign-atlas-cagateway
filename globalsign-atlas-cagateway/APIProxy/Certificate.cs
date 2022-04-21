using CSS.PKI;

using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy
{
	public class CertificateResponse
	{
		[JsonProperty("certificate")]
		public string Certificate { get; set; }

		[JsonProperty("status")]
		public string Status { get; set; }

		[JsonProperty("description")]
		public string Description { get; set; }
	}

	public class CertificateStatusResponse
	{
		[JsonProperty("not_after")]
		public long NotAfter { get; set; }

		[JsonProperty("not_before")]
		public long NotBefore { get; set; }

		[JsonProperty("serial_number")]
		public string SerialNumber { get; set; }
	}

	public class CertificateDetailsResponse
	{
		public CertificateResponse Cert { get; set; }
		public CertificateStatusResponse Status { get; set; }
	}
}