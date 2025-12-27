control 'SV-48300' do
  title 'Access to the Windows Store must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoUseStoreOpenWith

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off access to the Store" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44978r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36680'
  tag rid: 'SV-48300r2_rule'
  tag stig_id: 'WN08-CC-000030'
  tag gtitle: 'WINCC-000030'
  tag fix_id: 'F-41435r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
