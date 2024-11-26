control 'SV-29526' do
  title 'The system is configured to autoplay removable media.'
  desc 'Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs and the music on audio media starts immediately.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive), and on network drives.  If you enable this policy, you can also disable Autoplay on all drives.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:   HKEY_LOCAL_MACHINE
Subkey:   \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name:	  NoDriveTypeAutorun
Type:   REG_DWORD
Value:   0x000000ff (255)

Note:  If the value for NoDriveTypeAutorun is entered manually, it should be entered as “ff” when Hexadecimal is selected or “255” with Decimal selected.  Using the policy specified in the Fix section will enter it correctly.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> “Turn off AutoPlay” to “Enabled:All Drives”.

Note:  This was previously configured in the checklist using the Security Option setting “MSS: (NoDriveTypeAutorun) Disable Autorun on all drives” set to “255, disable Autorun for all drives”.  This updates the same registry value (NoDriveTypeAutorun) as the Administrative Template.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-24202r1_chk'
  tag severity: 'high'
  tag gid: 'V-2374'
  tag rid: 'SV-29526r1_rule'
  tag gtitle: 'Disable Media Autoplay'
  tag fix_id: 'F-20417r1_fix'
  tag 'documentable'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
