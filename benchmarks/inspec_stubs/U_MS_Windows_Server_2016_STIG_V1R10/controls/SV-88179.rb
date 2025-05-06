control 'SV-88179' do
  title 'Downloading print driver packages over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system. 

This setting prevents the computer from downloading print driver packages over HTTP.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableWebPnPDownload

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off downloading of print drivers over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73527'
  tag rid: 'SV-88179r1_rule'
  tag stig_id: 'WN16-CC-000160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-79969r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
