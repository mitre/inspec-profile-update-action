control 'SV-104265' do
  title 'Symantec ProxySG must use Transport Layer Security (TLS) to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).'
  desc 'check', 'Verify that only FIPS-compliant HMAC algorithms are in use.

1. Log on to the ProxySG CLI via SSH.
2. Type "show management services".
3. Verify the "Cipher Suite" attribute lists only cipher suites that use FIPS-compliant HMAC algorithms.

If any cipher suites are listed that use non-FIPS-compliant HMAC algorithms, this is a finding.'
  desc 'fix', 'Configure the ProxySG to use only FIPS-compliant HMAC algorithms.

1. Log on to the ProxySG SSH CLI.
2. Type "enable" and enter the enable password.
3. Type "configure terminal" and press "Enter".
 4. Type "management-services" and press "Enter". Type "edit HTTPS-Console" and press "Enter".
 5. Type "view" to display the list of configured cipher suites.
 6. Type "attribute cipher-suite" followed by a space-delimited list of only cipher suites from step 5 that use FIPS-compliant HMAC algorithms and press "Enter".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93497r1_chk'
  tag severity: 'high'
  tag gid: 'V-94311'
  tag rid: 'SV-104265r1_rule'
  tag stig_id: 'SYMP-AG-000490'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-100427r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
