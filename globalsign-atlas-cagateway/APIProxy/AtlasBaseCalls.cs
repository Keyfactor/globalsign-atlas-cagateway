using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.APIProxy
{
	public abstract class AtlasBaseRequest
	{
		[JsonIgnore]
		public string Resource { get; internal set; }

		[JsonIgnore]
		public string Method { get; internal set; }

		[JsonIgnore]
		public string TargetURI { get; set; }

		public string BuildParameters()
		{
			return "";
		}
	}
}