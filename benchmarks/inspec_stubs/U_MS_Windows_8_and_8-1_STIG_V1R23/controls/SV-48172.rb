control 'SV-48172' do
  title 'User Account Control approval mode for the built-in Administrator must be enabled.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "User Account Control: Admin Approval Mode for the Built-in Administrator account" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44872r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14234'
  tag rid: 'SV-48172r2_rule'
  tag stig_id: 'WN08-SO-000077'
  tag gtitle: 'UAC - Admin Approval Mode'
  tag fix_id: 'F-41310r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
