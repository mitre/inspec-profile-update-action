control 'SV-203685' do
  title 'The operating system must display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end an operating system session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. Logoff messages can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote logon, information systems typically send logoff messages as final messages prior to terminating sessions.'
  desc 'check', 'Verify the operating system displays an explicit logoff message to users indicating the reliable termination of authenticated communications sessions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to display an explicit logoff message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3810r374942_chk'
  tag severity: 'medium'
  tag gid: 'V-203685'
  tag rid: 'SV-203685r379342_rule'
  tag stig_id: 'SRG-OS-000281-GPOS-00111'
  tag gtitle: 'SRG-OS-000281'
  tag fix_id: 'F-3810r374943_fix'
  tag 'documentable'
  tag legacy: ['V-57211', 'SV-71471']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
