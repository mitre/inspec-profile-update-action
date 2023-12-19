control 'SV-207433' do
  title 'VMMs requiring user access authentication must provide a logout capability for user-initiated communications sessions.'
  desc 'If a user cannot explicitly end a VMM session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. For some types of interactive sessions, including, for example, remote login, VMMs typically send logout messages as final messages prior to terminating sessions.'
  desc 'check', 'Verify VMMs requiring user access authentication provide a logout capability for user-initiated communications sessions.

If they do not, this is a finding.'
  desc 'fix', 'Configure VMMs requiring user access authentication to provide a logout capability for user-initiated communications sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7690r365709_chk'
  tag severity: 'medium'
  tag gid: 'V-207433'
  tag rid: 'SV-207433r854608_rule'
  tag stig_id: 'SRG-OS-000280-VMM-001020'
  tag gtitle: 'SRG-OS-000280'
  tag fix_id: 'F-7690r365710_fix'
  tag 'documentable'
  tag legacy: ['V-57067', 'SV-71327']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
