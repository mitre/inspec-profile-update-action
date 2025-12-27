control 'SV-253372' do
  title 'Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.'
  desc 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce "Good, unknown and bad but critical" (preventing "bad"). By being launched first by the kernel, ELAM ( Early Launch Antimalware) is ensured to be launched before any third-party software, and is therefore able to detect malware in the boot process and prevent it from initializing.'
  desc 'check', 'The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce "Good, unknown and bad but critical" (preventing "bad").

If the registry value name below does not exist, this is a finding.

If it exists and is configured with a value of "7", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch\\

Value Name: DriverLoadPolicy

Value Type: REG_DWORD
Value: 1, 3, or 8 

Possible values for this setting are:
8 - Good only
1 - Good and unknown
3 - Good, unknown and bad but critical
7 - All (which includes "Bad" and would be a finding)'
  desc 'fix', 'Ensure that Early Launch Antimalware - Boot-Start Driver Initialization policy is set to enforce "Good, unknown and bad but critical" (preventing "bad").

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> System >> Early Launch Antimalware >> "Boot-Start Driver Initialization Policy" to "Enabled with "Good, unknown and bad but critical" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56825r829198_chk'
  tag severity: 'medium'
  tag gid: 'V-253372'
  tag rid: 'SV-253372r829200_rule'
  tag stig_id: 'WN11-CC-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56775r829199_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
