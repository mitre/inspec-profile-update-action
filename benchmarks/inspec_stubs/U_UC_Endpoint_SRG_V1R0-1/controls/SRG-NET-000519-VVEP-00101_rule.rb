control 'SRG-NET-000519-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint must display an explicit logout message to users indicating the reliable termination of communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Logout messages for access, for example, can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions including, for example, remote login, information systems typically send logout messages as final messages prior to terminating sessions.
 
This applies to network elements that have the concept of a user account and have the login function residing on the network element.'
  desc 'check', 'Verify the Unified Communications Endpoint displays an explicit logout message to users indicating the termination of communications sessions.

If the Unified Communications Endpoint does not display an explicit logout message to users, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to display an explicit logout message to users indicating the termination of communications sessions.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000519-VVEP-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000519-VVEP-00101'
  tag rid: 'SRG-NET-000519-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000519-VVEP-00101'
  tag gtitle: 'SRG-NET-000519-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000519-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
