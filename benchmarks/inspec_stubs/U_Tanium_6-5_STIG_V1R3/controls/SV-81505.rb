control 'SV-81505' do
  title 'Common Access Card (CAC)-based authentication must be enabled on the Tanium Server for network access with non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication.

Factors include:
(i) Something you know (e.g., password/PIN);
(ii) Something you have (e.g., cryptographic identification device, token); or
(iii) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Access the Tanium server interactively and log on as an Administrator.

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
     Note: This registry value requires that Tanium validate every CAC/PIV authentication attempt with AD to determine the state of the account that’s logging in. It must use the syntax of LDAP://<AD instance FQDN>

If the value for REG_DWORD "ForceSOAPSSLClientCert" is not set to "1" and the remaining registry values are not configured, this is a finding.'
  desc 'fix', 'Use the vendor documentation titled "Enabling SmartCard Authentication in Tanium 6.5+" to implement correct configuration settings for this requirement.

Vendor documentation can be downloaded from the following URL: https://kb.tanium.com/Smart_Card_Authentication.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67651r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67015'
  tag rid: 'SV-81505r2_rule'
  tag stig_id: 'TANS-CN-000011'
  tag gtitle: 'SRG-APP-000150'
  tag fix_id: 'F-73115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
