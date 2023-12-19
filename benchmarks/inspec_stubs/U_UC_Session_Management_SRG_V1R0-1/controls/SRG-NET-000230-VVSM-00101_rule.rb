control 'SRG-NET-000230-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to use FIPS-validated SHA-2 or higher to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised hashing standard and is being phased out of use by industry and government standards. Unless required for legacy use, DOD systems should not be configured to use SHA-2 for integrity of remote access sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).

This requirement applies only to network elements that act as an intermediary for individual sessions (e.g., proxy, ALG, or SSL VPN).'
  desc 'check', 'Verify the Unified Communications Session Manager is configured to use FIPS-validated SHA-2 or higher to protect the authenticity of communications sessions.

If the Unified Communications Session Manager is not configured to use FIPS-validated SHA-2 or higher, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to use FIPS-validated SHA-2 or higher to protect communications sessions.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000230-VVSM-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000230-VVSM-00101'
  tag rid: 'SRG-NET-000230-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000230-VVSM-00101'
  tag gtitle: 'SRG-NET-000230-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000230-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
