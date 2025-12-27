control 'SV-207225' do
  title 'The VPN Gateway must recognize only system-generated session identifiers.'
  desc "VPN gateways (depending on function) utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the valid user's application session can be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to any VPN gateway that is an intermediary of individual sessions (e.g., proxy, ALG, TLS VPN). VPN gateways that perform these functions must be able to identify which session identifiers were generated when the sessions were established."
  desc 'check', 'Verify the VPN Gateway recognizes only system-generated session identifiers.

If the VPN Gateway does not recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to recognize only system-generated session identifiers.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7485r378296_chk'
  tag severity: 'medium'
  tag gid: 'V-207225'
  tag rid: 'SV-207225r608988_rule'
  tag stig_id: 'SRG-NET-000233-VPN-000800'
  tag gtitle: 'SRG-NET-000233'
  tag fix_id: 'F-7485r378297_fix'
  tag 'documentable'
  tag legacy: ['V-97129', 'SV-106267']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
