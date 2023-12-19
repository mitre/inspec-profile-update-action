control 'SV-29401' do
  title 'Auditing Access of Global System Objects must be turned off.'
  desc 'This setting prevents the system from setting up a default system access control list for certain system objects, which could create a very large number of security events, filling the security log in Windows and making it difficult to identify actual issues.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for "Audit: Audit the access of global system objects" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name: AuditBaseObjects

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Audit: Audit the access of global system objects" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-46898r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14228'
  tag rid: 'SV-29401r2_rule'
  tag gtitle: 'Audit Access of Global System Objects'
  tag fix_id: 'F-45019r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
