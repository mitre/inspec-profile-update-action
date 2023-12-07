control 'SV-225318' do
  title 'Domain users must be required to elevate when setting a networks location.'
  desc 'Selecting an incorrect network location may allow greater exposure of a system.  Elevation is required by default on nondomain systems to change network location.  This setting configures elevation to also be required on domain-joined systems.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

Value Name: NC_StdDomainUserSetLocation

Type: REG_DWORD
Value: 1'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Require domain users to elevate when setting a network's location" to "Enabled".)
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27017r471296_chk'
  tag severity: 'low'
  tag gid: 'V-225318'
  tag rid: 'SV-225318r569185_rule'
  tag stig_id: 'WN12-CC-000005'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27005r471297_fix'
  tag 'documentable'
  tag legacy: ['V-21960', 'SV-53182']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
