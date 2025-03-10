control 'SV-226186' do
  title 'Autoplay must be disabled for all drives.'
  desc 'Allowing Autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon media is inserted into the drive.  As a result, the setup file of programs or music on audio media may start.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives.  Enabling this policy disables Autoplay on all drives.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Turn off AutoPlay" to "Enabled:All Drives".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27888r475881_chk'
  tag severity: 'high'
  tag gid: 'V-226186'
  tag rid: 'SV-226186r794479_rule'
  tag stig_id: 'WN12-CC-000074'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-27876r475882_fix'
  tag 'documentable'
  tag legacy: ['SV-52879', 'V-2374']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
