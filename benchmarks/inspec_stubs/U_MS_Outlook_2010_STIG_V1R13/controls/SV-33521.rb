control 'SV-33521' do
  title 'Junk Mail UI must be configured.'
  desc "The Junk E-mail Filter in Outlook is designed to intercept the most obvious junk e-mail, or spam, and send it to users' Junk E-mail folders. The filter evaluates each incoming message based on several factors, including the time when the message was sent and the content of the message. The filter does not single out any particular sender or message type, but instead analyzes each message based on its content and structure to discover whether or not it is probably spam. 
By default, the Junk E-mail Filter in Outlook is enabled. If this configuration is changed, users can receive large amounts of junk e-mail in their Inboxes, which could make it difficult for them to work with business-related e-mail messages."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Hide Junk Mail UI” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook

Criteria: If the value DisableAntiSpam is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Hide Junk Mail UI” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34008r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17624'
  tag rid: 'SV-33521r1_rule'
  tag stig_id: 'DTOO221 - Outlook'
  tag gtitle: 'DTOO221 - Junk Mail UI'
  tag fix_id: 'F-29696r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
