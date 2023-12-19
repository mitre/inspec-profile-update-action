control 'SV-253821' do
  title 'Multifactor authentication must be enabled on the Tanium Server for network access with privileged accounts.'
  desc 'The Tanium application must be configured to use multifactor authentication. Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
1. Something a user knows (e.g., password/PIN); 
2. Something a user has (e.g., cryptographic identification device, token); or 
3. Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

5. Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

7. Validate the following keys exist and are configured:

REG_SZ "ClientCertificateAuthField"
For example:
X509v3 Subject Alternative Name

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary.

REG_SZ "ClientCertificateAuth"
For example:
C:\\Program Files\\Tanium\\Tanium Server\\cac.pem

REG_SZ "TrustedHostList"
For example:
127.0.0.1 (for IPv4) and [::1] (for IPv6)

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Smartcard authentication" to implement correct configuration settings for this requirement. The documentation is at https://docs.tanium.com/platform_deployment_reference/platform_deployment_reference/smart_card_authentication.html?Highlight=cac.

1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

5. Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

6. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> WOW6432Node >> Tanium >> Tanium Server.

7. Configure the following keys:

REG_SZ "ClientCertificateAuthField"
For example:
X509v3 Subject Alternative Name

REG_SZ "ClientCertificateAuthRegex"
For example-DoD:
.+?Name:\\s*?(\\S+@[._a-zA-Z0-9]+).*
Note: This regex may vary.

REG_SZ "ClientCertificateAuth"
For example:
C:\\Program Files\\Tanium\\Tanium Server\\cac.pem

REG_SZ "TrustedHostList"
For example:
Append 127.0.0.1 (for IPv4) and [::1] (for IPv6)'
  impact 0.7
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57273r842489_chk'
  tag severity: 'high'
  tag gid: 'V-253821'
  tag rid: 'SV-253821r858410_rule'
  tag stig_id: 'TANS-CN-000010'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-57224r842490_fix'
  tag satisfies: ['SRG-APP-000151']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000767']
  tag nist: ['IA-2 (1)', 'IA-2 (3)']
end
