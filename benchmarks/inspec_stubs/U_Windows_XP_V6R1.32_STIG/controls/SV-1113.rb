control 'SV-1113' do
  title 'The built-in guest account is not disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.  This account is a member of the Everyone user group and has all the rights and permissions associated with that group, which could subsequently provide access to system resources to anonymous users.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Accounts: Guest account status” is not set to ” Disabled”, then this is a finding.'
  desc 'fix', 'Configure the system to disable the built-in guest Account.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-394r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1113'
  tag rid: 'SV-1113r1_rule'
  tag gtitle: 'Disable Guest Account'
  tag fix_id: 'F-5759r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
