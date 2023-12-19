control 'SV-228437' do
  title 'The remember password for internet e-mail accounts must be disabled.'
  desc "Use this option to hide your user's ability to cache passwords locally in the computer's registry. When configured, this policy will hide the 'Remember Password' checkbox and not allow users to have Outlook remember their password. Note that POP3, IMAP, and HTTP e-mail accounts are all considered Internet e-mail accounts in Outlook. E-mail account options are listed on the Server Type dialog box when users choose 'New' under Tools | Account Settings."
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Disable 'Remember password' for Internet e-mail accounts" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\16.0\outlook\security

Criteria: If the value EnableRememberPwd is REG_DWORD = 0, this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Disable 'Remember password' for Internet e-mail accounts" to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30670r497633_chk'
  tag severity: 'medium'
  tag gid: 'V-228437'
  tag rid: 'SV-228437r508021_rule'
  tag stig_id: 'DTOO237'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-30655r497634_fix'
  tag 'documentable'
  tag legacy: ['SV-85777', 'V-71153']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
