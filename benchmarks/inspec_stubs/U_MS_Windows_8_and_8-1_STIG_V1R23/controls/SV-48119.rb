control 'SV-48119' do
  title 'Media Player must be configured to prevent automatic Codec downloads.'
  desc 'The Windows Media Player uses software components, referred to as Codecs, to play back media files. By default, when an unknown file type is opened with the Media Player, it will search the Internet for the appropriate Codec and automatically download it. To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_CURRENT_USER
Subkey: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: PreventCodecDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback -> "Prevent Codec Download" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3481'
  tag rid: 'SV-48119r1_rule'
  tag stig_id: 'WN08-UC-000013'
  tag gtitle: 'Media Player - Prevent Codec Download'
  tag fix_id: 'F-41256r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
