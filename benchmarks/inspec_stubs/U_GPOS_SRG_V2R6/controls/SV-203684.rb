control 'SV-203684' do
  title 'The operating system must provide a logoff capability for user-initiated communications sessions when requiring user access authentication.'
  desc 'If a user cannot explicitly end an operating system session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. For some types of interactive sessions, including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'Verify the operating system provides a logoff capability for user-initiated communications sessions when requiring user access authentication. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide a logoff capability for user-initiated communications sessions when requiring user access authentication.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3809r374939_chk'
  tag severity: 'medium'
  tag gid: 'V-203684'
  tag rid: 'SV-203684r851752_rule'
  tag stig_id: 'SRG-OS-000280-GPOS-00110'
  tag gtitle: 'SRG-OS-000280'
  tag fix_id: 'F-3809r374940_fix'
  tag 'documentable'
  tag legacy: ['V-57209', 'SV-71469']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
