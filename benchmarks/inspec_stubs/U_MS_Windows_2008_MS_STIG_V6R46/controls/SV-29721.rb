control 'SV-29721' do
  title 'Media Player is configured to allow automatic CODEC downloads.'
  desc 'The Windows Media Player uses software components, referred to as CODECs, to play back media files.  By default, when an unknown file type is opened with the Media Player it will search the Internet for the appropriate CODEC and automatically download it.  To ensure platform consistency and to protect against new vulnerabilities associated with media types, all CODECs must be installed by the System Administrator.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:

Registry Hive:	HKEY_Current_User
Subkey: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\
Value Name:	PreventCodecDownload
Type: 		REG_DWORD
Value:		1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback “Prevent Codec Download” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-2049r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3481'
  tag rid: 'SV-29721r1_rule'
  tag gtitle: 'Media Player - Prevent Codec Download'
  tag fix_id: 'F-5993r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
