control 'SV-206465' do
  title 'The Central Log Server must use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

Anti-replay is a cryptographically based mechanism; thus, it must use FIPS-approved algorithms. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Note that the anti-replay service is implicit when data contains monotonically increasing sequence numbers and data integrity is assured. Use of DoD PKI is inherently compliant with this requirement for user and device access. Use of Transport Layer Security (TLS), including application protocols, such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security protocol is also complaint.

Configure the information system to use the hash message authentication code (HMAC) algorithm for authentication services to Kerberos, SSH, web management tool, and any other access method.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.

If the Central Log Server does not use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'This requirement applies to all privileged user accounts used for network logon to the application.

Configure the Central Log Server to use FIPS-validated SHA-1 or higher hash function to provide replay-resistant authentication mechanisms for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6725r285639_chk'
  tag severity: 'medium'
  tag gid: 'V-206465'
  tag rid: 'SV-206465r855295_rule'
  tag stig_id: 'SRG-APP-000156-AU-002380'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-6725r285640_fix'
  tag 'documentable'
  tag legacy: ['SV-96031', 'V-81317']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
