control 'SV-224924' do
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad.'
  desc 'Compromised boot drivers can introduce malware prior to protection mechanisms that load after initialization. The Early Launch Antimalware driver can limit allowed drivers based on classifications determined by the malware protection application. At a minimum, drivers determined to be bad must not be allowed.'
  desc 'check', 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy to enforce "Good, unknown and bad but critical" (preventing "bad").

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0x00000007 (7)", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch\\

Value Name: DriverLoadPolicy

Value Type: REG_DWORD
Value: 0x00000001 (1), 0x00000003 (3), or 0x00000008 (8) (or if the Value Name does not exist)

Possible values for this setting are:
8 - Good only
1 - Good and unknown
3 - Good, unknown and bad but critical
7 - All (which includes "bad" and would be a finding)'
  desc 'fix', 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy to enforce "Good, unknown and bad but critical" (preventing "bad").

If this needs to be corrected or a more secure setting is desired, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Early Launch Antimalware >> "Boot-Start Driver Initialization Policy" to "Not Configured" or "Enabled" with any option other than "All" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26615r465674_chk'
  tag severity: 'medium'
  tag gid: 'V-224924'
  tag rid: 'SV-224924r569186_rule'
  tag stig_id: 'WN16-CC-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26603r465675_fix'
  tag 'documentable'
  tag legacy: ['SV-88173', 'V-73521']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
