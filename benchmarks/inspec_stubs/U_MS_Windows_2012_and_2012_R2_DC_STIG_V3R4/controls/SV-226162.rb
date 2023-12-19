control 'SV-226162' do
  title 'Downloading print driver packages over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents the computer from downloading print driver packages over HTTP.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableWebPnPDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off downloading of print drivers over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27864r475809_chk'
  tag severity: 'medium'
  tag gid: 'V-226162'
  tag rid: 'SV-226162r794424_rule'
  tag stig_id: 'WN12-CC-000032'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27852r475810_fix'
  tag 'documentable'
  tag legacy: ['SV-52998', 'V-14260']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
