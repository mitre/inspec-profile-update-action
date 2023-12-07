control 'SV-6272' do
  title 'The system is configured to autoplay removable media.'
  desc 'Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs and the music on audio media starts immediately.  By default, Autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive), and on network drives.  If you enable this policy, you can also disable Autoplay on all drives.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> “Turn off AutoPlay” to “Enabled:All Drives”.

Note:  This was previously configured in the checklist using the Security Option setting “MSS: (NoDriveTypeAutorun) Disable Autorun on all drives” set to “255, disable Autorun for all drives”.  This updates the same registry value (NoDriveTypeAutorun) as the Administrative Template.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-2374'
  tag rid: 'SV-6272r1_rule'
  tag gtitle: 'Disable Media Autoplay'
  tag fix_id: 'F-20417r1_fix'
  tag 'documentable'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
