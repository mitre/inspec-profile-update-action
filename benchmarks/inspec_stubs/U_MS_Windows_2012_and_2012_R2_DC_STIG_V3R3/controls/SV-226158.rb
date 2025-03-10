control 'SV-226158' do
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'
  desc 'Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization.  The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application.  At a minimum, drivers determined to be bad must not be allowed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Policies\\EarlyLaunch\\

Value Name: DriverLoadPolicy

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware -> "Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27860r475797_chk'
  tag severity: 'medium'
  tag gid: 'V-226158'
  tag rid: 'SV-226158r794497_rule'
  tag stig_id: 'WN12-CC-000027'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27848r475798_fix'
  tag 'documentable'
  tag legacy: ['SV-51608', 'V-36679']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
