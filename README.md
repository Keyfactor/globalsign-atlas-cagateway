
# GlobalSign Atlas AnyGateway

This integration allows for the Synchronization, Enrollment, and Revocation of TLS Certificates from the GlobalSign Atlas platform.

#### Integration status: Production - Ready for use in production environments.

## About the Keyfactor AnyCA Gateway DCOM Connector

This repository contains an AnyCA Gateway Connector, which is a plugin to the Keyfactor AnyGateway. AnyCA Gateway Connectors allow Keyfactor Command to be used for inventory, issuance, and revocation of certificates from a third-party certificate authority.

## Support for GlobalSign Atlas AnyGateway

GlobalSign Atlas AnyGateway is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

---


---





## Keyfactor AnyCA Gateway Framework Supported
The Keyfactor gateway framework implements common logic shared across various gateway implementations and handles communication with Keyfactor Command. The gateway framework hosts gateway implementations or plugins that understand how to communicate with specific CAs. This allows you to integrate your third-party CAs with Keyfactor Command such that they behave in a manner similar to the CAs natively supported by Keyfactor Command.




This gateway extension was compiled against version  of the AnyCA Gateway DCOM Framework.  You will need at least this version of the framework Installed. If you have a later AnyGateway Framework Installed you will probably need to add binding redirects in the CAProxyServer.exe.config file to make things work properly.


[Keyfactor CAGateway Install Guide](https://software.keyfactor.com/Guides/AnyGateway_Generic/Content/AnyGateway/Introduction.htm)



---


# Introduction
This AnyGateway plug-in enables issuance, revocation, and synchronization of certificates from GlobalSign's Atlas platform.  
# Prerequisites

## Port Access
The GlobalSign Atlas CA Gateway makes outbound connections on port 8443. Make sure that port is accessible for outbound communications.

## mTLS Certificate
The mTLS certificate obtained from GlobalSign to use as the client certificate should be installed in the local machine certificate store on the Gateway server
The gateway service account (default Network Service) should be granted Read permission on the private key of the certificate

## Certificate Chain

In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you create your Root and/or Subordinate CA, make sure to import the certificate chain into the AnyGateway and Command Server certificate store

# Install
* Download latest successful build from [GitHub Releases](/releases/latest)

* Copy GlobalSignAtlasCAGateway.dll to the Program Files\Keyfactor\Keyfactor AnyGateway directory

* Update the CAProxyServer.config file
  * Update the CAConnection section to point at the GlobalSignCAProxy class
  ```xml
  <alias alias="CAConnector" type="Keyfactor.Extensions.AnyGateway.GlobalSign.Atlas.GlobalSignAtlasCAConnector, GlobalSignAtlasCAGateway"/>
  ```

# Configuration
The following sections will breakdown the required configurations for the AnyGatewayConfig.json file that will be imported to configure the AnyGateway.

## Templates
The Template section will map the CA's SSL profile to an AD template.
* ```ProductID```
Not used for the Atlas gateway, but cannot be left blank
* ```Lifetime```
The lifetime to use for enrollment, in days.
* ```KeyUsage```
The key usage to use for enrolled certs. Valid values are 'client', 'server', and 'clientserver'

 ```json
  "Templates": {
	"WebServer": {
      "ProductID": "certificate",
      "Parameters": {
		"Lifetime":"365",
        "KeyUsage":"clientserver"
      }
   }
}
 ```
## Security
The security section does not change specifically for the GlobalSign CA Gateway.  Refer to the AnyGateway Documentation for more detail.
```json
  /*Grant permissions on the CA to users or groups in the local domain.
	READ: Enumerate and read contents of certificates.
	ENROLL: Request certificates from the CA.
	OFFICER: Perform certificate functions such as issuance and revocation. This is equivalent to "Issue and Manage" permission on the Microsoft CA.
	ADMINISTRATOR: Configure/reconfigure the gateway.
	Valid permission settings are "Allow", "None", and "Deny".*/
    "Security": {
        "Keyfactor\\Administrator": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },
        "Keyfactor\\gateway_test": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        },		
        "Keyfactor\\SVC_TimerService": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "None"
        },
        "Keyfactor\\SVC_AppPool": {
            "READ": "Allow",
            "ENROLL": "Allow",
            "OFFICER": "Allow",
            "ADMINISTRATOR": "Allow"
        }
    }
```
## CerificateManagers
The Certificate Managers section is optional.
	If configured, all users or groups granted OFFICER permissions under the Security section
	must be configured for at least one Template and one Requester. 
	Uses "<All>" to specify all templates. Uses "Everyone" to specify all requesters.
	Valid permission values are "Allow" and "Deny".
```json
  "CertificateManagers":{
		"DOMAIN\\Username":{
			"Templates":{
				"MyTemplateShortName":{
					"Requesters":{
						"Everyone":"Allow",
						"DOMAIN\\Groupname":"Deny"
					}
				},
				"<All>":{
					"Requesters":{
						"Everyone":"Allow"
					}
				}
			}
		}
	}
```
## CAConnection
The CA Connection section will determine the API endpoint and configuration data used to connect to the GlobalSign Atlas CA. 
* ```ApiKey```
The API key for the Atlas credentials the gateway will use.  
* ```ApiSecret```
The corresponding API secret value that matches with the ApiKey
* ```ClientCertificate```
The location and thumbprint of the client auth certificate to use with the Atlas API
* ```SyncStartDate```
The earliest date to go back when doing a full sync
* ```PickupRetries```
(OPTIONAL)This is the number of times the AnyGateway will attempt to pickup an new certificate before reporting an error. This setting applies to new, renewed, or reissued certificates. Default is 5.
* ```PickupDelay```
(OPTIONAL)This is the number of seconds between retries when attempting to download a certificate. Default is 5.

```json
  "CAConnection": {
	"ApiKey":"<api key>",
	"ApiSecret":"<api secret>",
	"ClientCertificate": {
		"StoreName": "My",
		"StoreLocation": "LocalMachine",
		"Thumbprint": "0123456789abcdef"
	},
	"SyncStartDate":"2022-01-01",
    "PickupRetries":5,
	"PickupDelay":5,
  },
```
## GatewayRegistration
There are no specific Changes for the GatewayRegistration section. Refer to the AnyGateway Documentation for more detail.
```json
  "GatewayRegistration": {
    "LogicalName": "AtlasCASandbox",
    "GatewayCertificate": {
      "StoreName": "CA",
      "StoreLocation": "LocalMachine",
      "Thumbprint": "bc6d6b168ce5c08a690c15e03be596bbaa095ebf"
    }
  }
```

## ServiceSettings
There are no specific Changes for the ServiceSettings section. Refer to the AnyGateway Documentation for more detail.
```json
  "ServiceSettings": {
    "ViewIdleMinutes": 8,
    "FullScanPeriodHours": 24,
	"PartialScanPeriodMinutes": 240 
  }
```


