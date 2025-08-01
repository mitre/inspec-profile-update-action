control 'SV-48227' do
  title 'The Order Prints Online wizard must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting ensures the "Order Prints Online" task is not available in File Explorer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoOnlinePrintsWizard

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off the "Order Prints" picture task" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44906r1_chk'
  tag severity: 'low'
  tag gid: 'V-15676'
  tag rid: 'SV-48227r1_rule'
  tag stig_id: 'WN08-CC-000042'
  tag gtitle: 'Order Prints Online'
  tag fix_id: 'F-41363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
