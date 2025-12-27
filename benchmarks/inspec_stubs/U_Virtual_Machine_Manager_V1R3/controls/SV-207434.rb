control 'SV-207434' do
  title 'The VMM must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'If a user cannot explicitly end a VMM session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session. Users need to be aware of whether or not the session has been terminated.

Information resources to which users gain access via authentication include, for example, local workstations and remote services. Logout messages can be displayed after authenticated sessions have been terminated. However, for some types of interactive sessions, including, for example, remote login, VMMs typically send logout messages as final messages prior to terminating sessions.'
  desc 'check', 'Verify the VMM displays an explicit logout message to users indicating the reliable termination of authenticated communications sessions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7691r365712_chk'
  tag severity: 'medium'
  tag gid: 'V-207434'
  tag rid: 'SV-207434r854609_rule'
  tag stig_id: 'SRG-OS-000281-VMM-001030'
  tag gtitle: 'SRG-OS-000281'
  tag fix_id: 'F-7691r365713_fix'
  tag 'documentable'
  tag legacy: ['V-57069', 'SV-71329']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
