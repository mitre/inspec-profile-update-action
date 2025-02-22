control 'SV-207254' do
  title 'The VPN Client logout function must be configured to terminate the session on/with the VPN Gateway.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

However, for some types of interactive sessions including, for example, remote login, information systems typically send logout messages as final messages prior to terminating sessions.

This applies to VPN gateways that have the concept of a user account and have the login function residing on the VPN gateway.'
  desc 'check', 'Verify the VPN Client logout function is configured to terminate the session on/with the VPN Gateway.

If the VPN Client logout function does not terminate the session on/with the VPN Gateway, this is a finding.'
  desc 'fix', 'Configure the VPN Client logout log out function must be configured to terminate the session on/with the VPN Gateway.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7514r378383_chk'
  tag severity: 'medium'
  tag gid: 'V-207254'
  tag rid: 'SV-207254r856725_rule'
  tag stig_id: 'SRG-NET-000518-VPN-002280'
  tag gtitle: 'SRG-NET-000518'
  tag fix_id: 'F-7514r378384_fix'
  tag 'documentable'
  tag legacy: ['V-97203', 'SV-106341']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
