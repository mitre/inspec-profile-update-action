control 'SV-207255' do
  title 'The VPN Client must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logout messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, remote login, information systems typically send logout messages as final messages prior to terminating sessions.

This applies to VPN gateways that have the concept of a user account and have the login function residing on the VPN gateway.'
  desc 'check', 'Verify the VPN Client displays an explicit logout message to users indicating the reliable termination of authenticated communications sessions.

If the VPN Client does not display an explicit logout message to users indicating the reliable termination of authenticated communications sessions, this is a finding.'
  desc 'fix', 'Configure the VPN Client to display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7515r378386_chk'
  tag severity: 'medium'
  tag gid: 'V-207255'
  tag rid: 'SV-207255r856726_rule'
  tag stig_id: 'SRG-NET-000519-VPN-002290'
  tag gtitle: 'SRG-NET-000519'
  tag fix_id: 'F-7515r378387_fix'
  tag 'documentable'
  tag legacy: ['SV-106343', 'V-97205']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
