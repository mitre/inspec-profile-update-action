control 'SV-48299' do
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must be enabled and configured to only Good and Unknown.'
  desc 'Compromised boot drivers can introduce malware prior to some protection mechanisms that load after initialization.  The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application.  At a minimum, drivers determined to be bad must not be allowed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Policies\\EarlyLaunch\\

Value Name: DriverLoadPolicy

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Early Launch Antimalware -> "Boot-Start Driver Initialization Policy" to "Enabled" with "Good and Unknown" selected.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36679'
  tag rid: 'SV-48299r2_rule'
  tag stig_id: 'WN08-CC-000027'
  tag gtitle: 'WINCC-000027'
  tag fix_id: 'F-41434r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECVP-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
