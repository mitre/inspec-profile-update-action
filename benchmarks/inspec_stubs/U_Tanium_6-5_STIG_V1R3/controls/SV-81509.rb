control 'SV-81509' do
  title 'Common Access Card (CAC)-based authentication must be enforced on the Tanium Server for authentication for local access with non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication is defined as: using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN);
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Access the Tanium Module server interactively and log on as an Administrator.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Validate the value for REG_DWORD "ForceSOAPSSLClientCert" is set to "1".

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server

Validate the following keys exist and are configured:
REG_SZ "ClientCertificateAuthField"

For example:
X509v3 Subject Alternative Name.
REG_SZ "ClientCertificateAuthRegex"

For example-DoD: 
.*\\:\\s*([^@]+)@.*$
     Note: This regex should be valid for any Subject Alternative Name entry.
REG_SZ "ClientCertificateAuth"
     Note: This registry value defines which certificate file to use for authentication.

For example:
C:\\Program Files\\Tanium\\Tanium Server\\dod.pem
REG_SZ "cac_ldap_server_url"
     Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that’s logging on. It must use the syntax of LDAP://<AD instance FQDN>

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Enabling SmartCard Authentication in Tanium 6.5+" to implement correct configuration settings for this requirement.

Vendor documentation can be downloaded from the following URL: https://kb.tanium.com/Smart_Card_Authentication.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67655r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67019'
  tag rid: 'SV-81509r1_rule'
  tag stig_id: 'TANS-CN-000013'
  tag gtitle: 'SRG-APP-000152'
  tag fix_id: 'F-73119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
