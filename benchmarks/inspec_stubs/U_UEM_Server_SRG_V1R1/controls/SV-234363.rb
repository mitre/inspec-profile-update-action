control 'SV-234363' do
  title 'The UEM server must use FIPS-validated SHA-2 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

Anti-replay is a cryptographically based mechanism; thus, it must use FIPS-approved algorithms. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Note that the anti-replay service is implicit when data contains monotonically increasing sequence numbers and data integrity is assured. Use of DoD PKI is inherently compliant with this requirement for user and device access. Use of Transport Layer Security (TLS), including application protocols, such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security protocol is also complaint.

Note: Although allowed by SP800-131Ar1 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards.

Configure the information system to use the hash message authentication code (HMAC) algorithm for authentication services to Kerberos, SSH, web management tool, and any other access method. 

'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server uses FIPS-validated SHA-2 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.

If the UEM server does not use FIPS-validated SHA-2 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure the UEM server to use FIPS-validated SHA-2 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37548r614099_chk'
  tag severity: 'high'
  tag gid: 'V-234363'
  tag rid: 'SV-234363r617407_rule'
  tag stig_id: 'SRG-APP-000156-UEM-000090'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-37513r614100_fix'
  tag satisfies: ['FIA \nReference:PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
