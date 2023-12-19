control 'SV-2374' do
  title 'The system is configured to autoplay removable media.'
  desc 'Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs and the music on audio media starts immediately.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive), and on network drives.  If you enable this policy, you can also disable Autoplay on all drives.'
  desc 'check', 'If the following registry values don’t exist or are not configured as specified this is a finding:

Registry Hive:   HKEY_LOCAL_MACHINE
Subkey:   \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name:	  NoDriveTypeAutorun
Type:   REG_DWORD
Value:   0x000000ff (255)

Note:  If the value for NoDriveTypeAutorun is entered manually, it should be entered as “ff” when Hexadecimal is selected or “255” with Decimal selected.  Using the policy specified in the Fix section will enter it correctly.

Value Name:	HonorAutorunSetting
Type:   REG_DWORD
Value:   1

If the following sample file is not at least at the version listed this is a finding (updated as part of Microsoft patches KB953252 (patch KB950582) or KB967715)

Shell32.dll
XP SP2 – 6.0.2900.3402
XP SP3 – 6.0.2900.5622
XP SP2 x64 – 6.0.3790.4315
2003 SP2 – 6.0.3790.4315'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> “Turn off AutoPlay” to “Enabled:All Drives”.

Note:  This was previously configured in the checklist using the Security Option setting “MSS: (NoDriveTypeAutorun) Disable Autorun on all drives” set to “255, disable Autorun for all drives”.  This updates the same registry value (NoDriveTypeAutorun) as the Administrative Template setting.

In addition to the above, Microsoft has released patches to correct issues with this setting.   The patches from either Microsoft’s KB953252 (patch KB950582) or KB967715 must be installed.  This will add the HonorAutorunSetting registry value and update the file referenced in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-24203r2_chk'
  tag severity: 'high'
  tag gid: 'V-2374'
  tag rid: 'SV-2374r2_rule'
  tag gtitle: 'Disable Media Autoplay'
  tag fix_id: 'F-20418r2_fix'
  tag 'documentable'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
