control 'SV-48214' do
  title 'Downloading print driver packages over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents the computer from downloading print driver packages over HTTP.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableWebPnPDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off downloading of print drivers over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14260'
  tag rid: 'SV-48214r1_rule'
  tag stig_id: 'WN08-CC-000032'
  tag gtitle: 'HTTP Printer Drivers'
  tag fix_id: 'F-41350r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
