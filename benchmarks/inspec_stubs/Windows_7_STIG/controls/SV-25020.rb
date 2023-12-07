control 'SV-25020' do
  title 'The built-in administrator account must be disabled.'
  desc 'The built-in administrator account is a well-known account subject to attack.  It also provides no accountability to individual administrators on a system.  It must be disabled to prevent its use.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Administrator account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60803r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16047'
  tag rid: 'SV-25020r2_rule'
  tag gtitle: 'Built-in Admin Account Status'
  tag fix_id: 'F-65535r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
