control 'SV-48065' do
  title 'Autoplay must be disabled for all drives.'
  desc 'Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may start.  By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives.  If you enable this policy, you can also disable autoplay on all drives.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)

Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is selected, or "255" with Decimal selected.  Using the policy value specified in the Fix section will enter it correctly.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Turn off AutoPlay" to "Enabled:All Drives".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44804r1_chk'
  tag severity: 'high'
  tag gid: 'V-2374'
  tag rid: 'SV-48065r1_rule'
  tag stig_id: 'WN08-CC-000074'
  tag gtitle: 'Disable Media Autoplay'
  tag fix_id: 'F-41203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
