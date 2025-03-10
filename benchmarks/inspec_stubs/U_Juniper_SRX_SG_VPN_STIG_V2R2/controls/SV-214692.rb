control 'SV-214692' do
  title 'The Juniper SRX Services Gateway VPN must configure Internet Key Exchange (IKE) with SHA1 or greater to protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This requirement focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).

An IPsec Security Associations (SA) is established using either IKE or manual configuration.'
  desc 'check', 'View all IKE proposals using in the VPN configuration.

[edit]
show security ike proposal

If the authentication algorithm in all IKE proposals is not set to SHA1 or higher, this is a finding.'
  desc 'fix', 'Include the SHA1 or higher authentication algorithm in the IKE proposal. The following is an example command.

[edit]
set security ike proposal <P1-PROPOSAL-NAME> authentication-algorithm sha-256'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15893r297663_chk'
  tag severity: 'high'
  tag gid: 'V-214692'
  tag rid: 'SV-214692r383107_rule'
  tag stig_id: 'JUSX-VN-000025'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-15891r297664_fix'
  tag 'documentable'
  tag legacy: ['V-66641', 'SV-81131']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
