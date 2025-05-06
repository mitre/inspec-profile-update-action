control 'SV-226369' do
  title 'Media Player must be configured to prevent automatic Codec downloads.'
  desc 'The Windows Media Player uses software components, referred to as Codecs, to play back media files.  By default, when an unknown file type is opened with the Media Player, it will search the Internet for the appropriate Codec and automatically download it.  To ensure platform consistency and to protect against new vulnerabilities associated with media types, all Codecs must be installed by the System Administrator.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: PreventCodecDownload

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> Playback -> "Prevent Codec Download" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28071r476951_chk'
  tag severity: 'medium'
  tag gid: 'V-226369'
  tag rid: 'SV-226369r569184_rule'
  tag stig_id: 'WN12-UC-000013'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-28059r476952_fix'
  tag 'documentable'
  tag legacy: ['SV-52921', 'V-3481']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
