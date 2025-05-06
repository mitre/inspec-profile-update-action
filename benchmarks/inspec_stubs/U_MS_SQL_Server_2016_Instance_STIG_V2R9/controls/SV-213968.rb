control 'SV-213968' do
  title 'SQL Server must enforce authorized access to all PKI private keys stored/utilized by SQL Server.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key. 
 
If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where SQL Server-stored private keys are used to authenticate SQL Server to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against SQL Server system and its clients. 
 
Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 or FIPS 140-3 validated cryptographic modules. 
 
All access to the private key(s) of SQL Server must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of SQL Server's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', 'Review system configuration to determine whether FIPS compliant support has been enabled. 
 
Start >> Control Panel >> Administrative Tools >> Local Security Policy >> Local Policies >> Security Options
 
Ensure that "System cryptography: Use FIPS-compliant algorithms for encryption, hashing, and signing" is enabled. 

If "System cryptography: Use FIPS-compliant algorithms for encryption, hashing, and signing" is not enabled, this is a finding. 
 
For more information, see https://support.microsoft.com/en-us/kb/3141890.'
  desc 'fix', 'Enable use of FIPS-compliant algorithms. 
 
Start >> Control Panel >> Administrative Tools >> Local Security Policy >> Local Policies >> Security Options 
 
Double-click "System cryptography: Use FIPS-compliant algorithms for encryption, hashing, and signing." 
 
Click Enabled >> Apply.'
  impact 0.7
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15185r863335_chk'
  tag severity: 'high'
  tag gid: 'V-213968'
  tag rid: 'SV-213968r879613_rule'
  tag stig_id: 'SQL6-D0-008400'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-15183r863336_fix'
  tag 'documentable'
  tag legacy: ['SV-93903', 'V-79197']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
