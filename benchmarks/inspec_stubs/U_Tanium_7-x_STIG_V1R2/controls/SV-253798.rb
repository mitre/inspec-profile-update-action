control 'SV-253798' do
  title 'The Tanium application must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12 and as a primary component of layered protection for national security systems.'
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
  desc 'fix', '1. Access the Tanium Server.

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
  tag check_id: 'C-57250r842420_chk'
  tag severity: 'medium'
  tag gid: 'V-253798'
  tag rid: 'SV-253798r850226_rule'
  tag stig_id: 'TANS-00-001420'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-57201r842421_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
