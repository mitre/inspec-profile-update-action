control 'SV-32291' do
  title 'The built-in guest account must be disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Guest account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60985r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1113'
  tag rid: 'SV-32291r2_rule'
  tag gtitle: 'Disable Guest Account'
  tag fix_id: 'F-65715r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
