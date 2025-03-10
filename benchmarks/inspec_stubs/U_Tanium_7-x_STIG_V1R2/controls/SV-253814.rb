control 'SV-253814' do
  title 'The Tanium application must retain the session lock until the user reestablishes access using established identification and authentication procedures.'
  desc 'Unattended systems are susceptible to unauthorized use and should be locked when unattended. This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the system.'
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

Vendor documentation can be downloaded from https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/smart_card_authentication.html?Highlight=cac.
 
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
  tag check_id: 'C-57266r842468_chk'
  tag severity: 'medium'
  tag gid: 'V-253814'
  tag rid: 'SV-253814r842470_rule'
  tag stig_id: 'TANS-CN-000001'
  tag gtitle: 'SRG-APP-000002'
  tag fix_id: 'F-57217r842469_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
