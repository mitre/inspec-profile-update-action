control 'SV-3384' do
  title 'The system is not configured to make the object creator the owner of objects created by administrators.'
  desc 'Either the object creator or the Administrators group owns objects created by members of the Administrators group.  In order to ensure accurate auditing and proper accountability, the default owner should be the object creator.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “System objects: Default owner for object created by members of the Administrators group” is not set to “Object creator”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  NoDefaultAdminOwner

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System objects: Default owner for object created by members of the Administrators group” to “Object creator”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-31r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3384'
  tag rid: 'SV-3384r1_rule'
  tag gtitle: 'Owner of Objects Created by Administrators'
  tag fix_id: 'F-60r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
