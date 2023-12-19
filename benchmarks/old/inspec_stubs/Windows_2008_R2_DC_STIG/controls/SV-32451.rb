control 'SV-32451' do
  title 'Domain users will be required to elevate when setting a network’s location.'
  desc 'This policy requires domain users to elevate when setting a network’s location.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name:  NC_StdDomainUserSetLocation

Type:  REG_DWORD
Value:  1'
  desc 'fix', "Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> “Require domain users to elevate when setting a network's location” to “Enabled”."
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-26849r1_chk'
  tag severity: 'low'
  tag gid: 'V-21960'
  tag rid: 'SV-32451r1_rule'
  tag gtitle: 'Elevate when setting a network’s location'
  tag fix_id: 'F-22948r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
