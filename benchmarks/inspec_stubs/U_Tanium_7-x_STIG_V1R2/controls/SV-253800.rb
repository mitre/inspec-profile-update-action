control 'SV-253800' do
  title 'The Tanium application must accept Personal Identity Verification (PIV) credentials from other federal agencies.'
  desc 'Access may be denied to authorized users if federal agency PIV credentials are not accepted. 

PIV credentials are issued by federal agencies and conform to FIPS Publication 201 and supporting guidance documents. OMB Memorandum 11-11 requires federal agencies to continue implementing the requirements specified in HSPD-12 to enable agencywide use of PIV credentials.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

7. Validate the following keys exist and are configured:

REG_SZ "ClientCertificateAuthField"
For example: 
X509v3 Subject Alternative Name.

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary. 

REG_SZ "ClientCertificateAuth"
For example:
C:\\Program Files\\Tanium\\Tanium Server\\dod.pem

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Smart card authentication" to implement correct configuration settings for this requirement. 

Vendor documentation can be downloaded from the following URL: https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/smart_card_authentication.html?Highlight=cac

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

7. Configure the following keys:

REG_SZ "ClientCertificateAuthField"
For example: 
X509v3 Subject Alternative Name.

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary. 

REG_SZ "ClientCertificateAuth"
For example:
C:\\Program Files\\Tanium\\Tanium Server\\dod.pem'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57252r842426_chk'
  tag severity: 'medium'
  tag gid: 'V-253800'
  tag rid: 'SV-253800r850237_rule'
  tag stig_id: 'TANS-00-001455'
  tag gtitle: 'SRG-APP-000402'
  tag fix_id: 'F-57203r842427_fix'
  tag 'documentable'
  tag cci: ['CCI-002009']
  tag nist: ['IA-8 (1)']
end
