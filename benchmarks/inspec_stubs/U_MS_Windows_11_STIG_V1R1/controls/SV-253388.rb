control 'SV-253388' do
  title 'Autoplay must be disabled for all drives.'
  desc 'Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as soon as media is inserted in the drive. As a result, the setup file of programs or music on audio media may start. By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. If this policy is enabled, autoplay can be disabled on all drives.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name: NoDriveTypeAutoRun

Value Type: REG_DWORD
Value: 0x000000ff (255)

Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is selected, or "255" with Decimal selected. Using the policy value specified in the Fix section will enter it correctly.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56841r829246_chk'
  tag severity: 'high'
  tag gid: 'V-253388'
  tag rid: 'SV-253388r829248_rule'
  tag stig_id: 'WN11-CC-000190'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-56791r829247_fix'
  tag 'documentable'
  tag cci: ['CCI-001734']
  tag nist: ['CM-10 (1)']
end
