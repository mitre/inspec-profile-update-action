control 'SV-48262' do
  title 'The built-in administrator account must be disabled.'
  desc 'The built-in administrator account is a well-known account subject to attack.  It also provides no accountability to individual administrators on a system.  It must be disabled to prevent its use.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Administrator account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44940r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16047'
  tag rid: 'SV-48262r1_rule'
  tag stig_id: 'WN08-SO-000001'
  tag gtitle: 'Built-in Admin Account Status'
  tag fix_id: 'F-41397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
