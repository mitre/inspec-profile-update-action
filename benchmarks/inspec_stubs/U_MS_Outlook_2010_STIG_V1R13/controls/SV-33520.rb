control 'SV-33520' do
  title "Recipients of sent email must be unable to be added to the safe sender's list."
  desc "Users could send e-mail messages to request that they be taken off a mailing list. If the e-mail recipient is then automatically added to the Safe Senders List, future e mail messages from that address will no longer be sent to the users Junk E-mail folder, even if it would otherwise be considered junk.
By default, recipients of outgoing messages are not added automatically to individual users' Safe Senders Lists. However, users can change this configuration in the Outlook user interface."
  desc 'check', "The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Add e-mail recipients to users' Safe Senders Lists” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value JunkMailTrustOutgoingRecipients is REG_DWORD = 0, this is not a finding."
  desc 'fix', "Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Add e-mail recipients to users' Safe Senders Lists” to “Disabled”."
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17558'
  tag rid: 'SV-33520r1_rule'
  tag stig_id: 'DTOO224 - Outlook'
  tag gtitle: 'DTOO224 - Email Recipient to Safe Sender List'
  tag fix_id: 'F-29695r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
