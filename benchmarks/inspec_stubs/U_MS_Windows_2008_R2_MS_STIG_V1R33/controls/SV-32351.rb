control 'SV-32351' do
  title 'Media Player will be configured to prevent automatic Codec downloads.'
  desc 'The Windows Media Player uses software components, referred to as Codecs, to play back media files.  By default, when an unknown file type is opened with the Media Player it will search the Internet for the appropriate Codec and automatically download it.  To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive:  HKEY_Current_User
Subkey:  \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name:  PreventCodecDownload

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback “Prevent Codec Download” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32898r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3481'
  tag rid: 'SV-32351r1_rule'
  tag gtitle: 'Media Player - Prevent Codec Download'
  tag fix_id: 'F-5993r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
