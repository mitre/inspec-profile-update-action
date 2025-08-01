control 'SV-235765' do
  title 'The download location prompt must be configured.'
  desc 'This setting provides positive feedback before a download starts, limiting the possibility of inadvertent downloads without notifying the user.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Ask where to save downloaded files" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PromptForDownloadLocation" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Ask where to save downloaded files" to "enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38984r626491_chk'
  tag severity: 'low'
  tag gid: 'V-235765'
  tag rid: 'SV-235765r626523_rule'
  tag stig_id: 'EDGE-00-000052'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38947r626492_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
