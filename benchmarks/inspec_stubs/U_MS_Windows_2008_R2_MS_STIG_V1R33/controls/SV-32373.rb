control 'SV-32373' do
  title 'Audit of Backup and Restore Privileges will be turned off.'
  desc 'This policy setting stops the system from generating audit events for every file backed up or restored which could fill the Security log in Windows.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.  

If the value for “Audit: Audit the use of Backup and Restore privilege” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name:  FullPrivilegeAuditing

Value Type:  REG_Binary
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Audit: Audit the use of Backup and Restore privilege” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-11574r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14229'
  tag rid: 'SV-32373r1_rule'
  tag gtitle: 'Audit Backup and Restore Privileges'
  tag fix_id: 'F-13553r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
