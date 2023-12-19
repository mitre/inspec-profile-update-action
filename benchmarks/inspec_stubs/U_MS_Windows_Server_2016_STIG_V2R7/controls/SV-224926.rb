control 'SV-224926' do
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
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26617r465680_chk'
  tag severity: 'medium'
  tag gid: 'V-224926'
  tag rid: 'SV-224926r569186_rule'
  tag stig_id: 'WN16-CC-000160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26605r465681_fix'
  tag 'documentable'
  tag legacy: ['V-73527', 'SV-88179']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
