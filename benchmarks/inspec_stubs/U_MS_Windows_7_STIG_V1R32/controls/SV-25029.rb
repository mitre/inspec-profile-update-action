control 'SV-25029' do
  title 'Audit policy using subcategories is enabled.'
  desc 'This policy setting allows administrators to enable the more precise auditing capabilities present in Windows Vista and later.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  SCENoApplyLegacyAuditPolicy

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-11575r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14230'
  tag rid: 'SV-25029r1_rule'
  tag gtitle: 'Audit Policy Subcategory Setting'
  tag fix_id: 'F-13554r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
