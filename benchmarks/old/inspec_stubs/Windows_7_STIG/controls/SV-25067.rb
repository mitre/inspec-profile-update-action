control 'SV-25067' do
  title 'The system must be configured to hide the computer from the browse list.'
  desc 'Identifying the computer name on a network could provide an attacker with information useful in gaining access.  This setting prevents the computer name from displaying in the browse list.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Lanmanserver\\Parameters\\

Value Name:  Hidden

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "MSS: (Hidden) Hide Computer From the Browse List (not recommended except for highly secure environments)" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60799r2_chk'
  tag severity: 'low'
  tag gid: 'V-14231'
  tag rid: 'SV-25067r3_rule'
  tag gtitle: 'Hide Computer'
  tag fix_id: 'F-65531r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
