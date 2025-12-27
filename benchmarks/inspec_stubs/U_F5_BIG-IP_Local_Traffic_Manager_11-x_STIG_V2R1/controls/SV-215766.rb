control 'SV-215766' do
  title 'The BIG-IP Core implementation must be configured to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS/TLS mutual authentication (two-way/bidirectional).'
  desc 'check', 'Verify the BIG-IP Core is configured to protect the authenticity of communications sessions. 

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> SSL >> Client

Verify a profile exists that is FIPS compliant.

Select FIPS-compliant profile.

Select "Advanced" next to "Configuration".

Verify "Ciphers" under "Configuration" section is configured to use FIPS-compliant ciphers.

Verify the BIG-IP Core is configured to use FIPS-compliant profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Server(s) from the list that the LTM module is managing the Client SSL side traffic.

Verify under "Configuration" section, that FIPS-compliant profile is in the "Selected" area for "SSL Profile (Client)".

If the BIG-IP Core is not configured to protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure BIG-IP Core to protect the authenticity of communications sessions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16958r291111_chk'
  tag severity: 'medium'
  tag gid: 'V-215766'
  tag rid: 'SV-215766r557356_rule'
  tag stig_id: 'F5BI-LT-000097'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-16956r291112_fix'
  tag 'documentable'
  tag legacy: ['SV-74743', 'V-60313']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
