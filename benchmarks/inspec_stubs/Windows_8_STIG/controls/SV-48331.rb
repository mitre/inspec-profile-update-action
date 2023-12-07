control 'SV-48331' do
  title 'The Enhanced Mitigation Experience Toolkit (EMET) Default Protections for Popular Software must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications.  The Enhanced Mitigation Experience Toolkit can enable several mechanisms, such as Data Execution Prevention (DEP), Address Space Layout Randomization (ASLR), and Structured Exception Handler Overwrite Protection (SEHOP) on the system and applications adding additional levels of protection.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

If EMET has not been installed and DEP and SEHOP are configured as required in V-68843 and V-68847, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\EMET\\Defaults\\
Value Type: REG_SZ (for each Value below)

Values noted as "Blank" are empty in the registry.

Value Name: *\\7-Zip\\7z.exe
Value: -EAF

Value Name: *\\7-Zip\\7zG.exe
Value: -EAF

Value Name: *\\7-Zip\\7zFM.exe
Value: -EAF

Value Name: *\\Adobe\\Adobe Photoshop CS*\\Photoshop.exe
Value: "Blank"

Value Name: *\\Foxit Reader\\Foxit Reader.exe
Value: "Blank"

Value Name: *\\Google\\Chrome\\Application\\chrome.exe
Value: +EAF+ eaf_modules:chrome_child.dll

Value Name: *\\Google\\Google Talk\\googletalk.exe
Value: -DEP

Value Name: *\\iTunes\\iTunes.exe
Value: "Blank"

Value Name: *\\Microsoft Lync\\communicator.exe
Value: "Blank"

Value Name: *\\mIRC\\mirc.exe
Value: "Blank"

Value Name: *\\Mozilla Firefox\\firefox.exe
Value: +EAF+ eaf_modules:mozjs.dll;xul.dll

Value Name: *\\Mozilla Firefox\\plugin-container.exe
Value: "Blank"

Value Name: *\\Mozilla Thunderbird\\plugin-container.exe
Value: "Blank"

Value Name: *\\Mozilla Thunderbird\\thunderbird.exe
Value: "Blank"

Value Name: *\\Opera\\*\\opera.exe
Value: "Blank"

Value Name: *\\Opera\\opera.exe
Value: "Blank"

Value Name: *\\Pidgin\\pidgin.exe
Value: "Blank"

Value Name: *\\QuickTime\\QuickTimePlayer.exe
Value: "Blank"

Value Name: *\\Real\\RealPlayer\\realconverter.exe
Value: "Blank"

Value Name: *\\Real\\RealPlayer\\realplay.exe
Value: "Blank"

Value Name: *\\Safari\\Safari.exe
Value: "Blank"

Value Name: *\\SkyDrive\\SkyDrive.exe
Value: "Blank"

Value Name: *\\Skype\\Phone\\Skype.exe
Value: -EAF

Value Name: *\\VideoLAN\\VLC\\vlc.exe
Value: "Blank"

Value Name: *\\Winamp\\winamp.exe
Value: "Blank"

Value Name: *\\Windows Live\\Mail\\wlmail.exe
Value: "Blank"

Value Name: *\\Windows Live\\Photo Gallery\\WLXPhotoGallery.exe
Value: "Blank"

Value Name: *\\Windows Live\\Writer\\WindowsLiveWriter.exe
Value:  "Blank"

Value Name: *\\Windows Media Player\\wmplayer.exe
Value: -EAF -MandatoryASLR

Value Name: *\\WinRAR\\rar.exe
Value: "Blank"

Value Name: *\\WinRAR\\unrar.exe
Value: "Blank"

Value Name: *\\WinRAR\\winrar.exe
Value: "Blank"

Value Name: *\\WinZip\\winzip32.exe
Value: "Blank"

Value Name: *\\WinZip\\winzip64.exe
Value: "Blank"

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> EMET >> "Default Protections for Popular Software" to "Enabled".

Note: The Enhanced Mitigation Experience Toolkit must be installed on the system and the administrative template files added to make this setting available.   

Due to a change in the registry structure for EMET 5.5, if the system has a previous version of EMET installed and configured, this setting needs to be set to "Not Configured" prior to the upgrade to EMET 5.5, and the new administrative template files copied to the appropriate area.  The setting can then be re-enabled.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-67363r5_chk'
  tag severity: 'medium'
  tag gid: 'V-36704'
  tag rid: 'SV-48331r7_rule'
  tag stig_id: 'WN08-CC-000081'
  tag gtitle: 'WINCC-000081'
  tag fix_id: 'F-72813r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
