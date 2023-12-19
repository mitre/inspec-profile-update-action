control 'SV-48437' do
  title 'Domain users must be required to elevate when setting a networks location.'
  desc 'Selecting an incorrect network location may allow greater exposure of a system.  Elevation is required by default on non-domain systems to change network location.  This setting configures elevation to also be required on domain-joined systems.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_StdDomainUserSetLocation

Type: REG_DWORD
Value: 1'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Require domain users to elevate when setting a network's location" to "Enabled".)
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45103r2_chk'
  tag severity: 'low'
  tag gid: 'V-21960'
  tag rid: 'SV-48437r2_rule'
  tag stig_id: 'WN08-CC-000005'
  tag gtitle: 'Elevate when setting a network’s location'
  tag fix_id: 'F-41565r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
