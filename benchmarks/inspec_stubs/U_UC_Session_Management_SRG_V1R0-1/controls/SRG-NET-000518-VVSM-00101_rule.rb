control 'SRG-NET-000518-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager requiring user access authentication must provide a logout capability for user-initiated communications sessions.'
  desc 'If a user cannot explicitly end a session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

However, for some types of interactive sessions including, for example, remote login, information systems typically send logout messages as final messages prior to terminating sessions.

This applies to network elements that have the concept of a user account and have the login function residing on the network element.'
  desc 'check', 'Verify the Unified Communications Session Manager requiring user access authentication provides a logout capability for user-initiated communications sessions.

If the Unified Communications Session Manager requiring user access authentication does not provide a logout capability for user-initiated communications sessions, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager requiring user access authentication to provide a logout capability for user-initiated communications sessions.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000518-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000518-VVSM-00101'
  tag rid: 'SRG-NET-000518-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000518-VVSM-00101'
  tag gtitle: 'SRG-NET-000518-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000518-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
