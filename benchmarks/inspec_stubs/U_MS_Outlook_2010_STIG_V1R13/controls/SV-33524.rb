control 'SV-33524' do
  title 'The "remember password" for internet e-mail accounts must be disabled.'
  desc "As a security precaution, password caching for eMail Internet protocols such as POP3 or IMAP may lead to password discovery and eventually to data loss.  An attacker that is able to access the users' profile may be able to acquire these cached passwords, they could then use this information to compromise the users' email accounts and other systems that use the same credentials."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Disable ‘Remember password’ for Internet e-mail accounts” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value EnableRememberPwd is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Disable ‘Remember password’ for Internet e-mail accounts” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17587'
  tag rid: 'SV-33524r1_rule'
  tag stig_id: 'DTOO237 - Outlook'
  tag gtitle: 'DTOO237-Disable "remember password" on eMail Accts'
  tag fix_id: 'F-29699r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
