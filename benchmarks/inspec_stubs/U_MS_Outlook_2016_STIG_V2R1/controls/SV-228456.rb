control 'SV-228456' do
  title 'Automatic sending  s/Mime receipt requests must be disallowed.'
  desc "This policy setting controls how Outlook handles S/MIME receipt requests. If you enable this policy setting, you can choose from four options for handling S/MIME receipt requests in Outlook:- Open message if receipt can't be sent- Don't open message if receipt can't be sent- Always prompt before sending receipt- Never send S/MIME receipts. If you disable or do not configure this policy setting, when users open messages with attached receipt requests, Outlook prompts them to decide whether to send a receipt to the sender with information about the identity of the user who opened the message and the time it was opened. If Outlook cannot send the receipt, the user is still allowed to open the message."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "S/MIME receipt requests behavior" is set to "Enabled (Never send S\\MIME receipts)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value RespondToReceiptRequests is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "S/MIME receipt requests behavior" to "Enabled (Never send S\\MIME receipts)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30689r497690_chk'
  tag severity: 'medium'
  tag gid: 'V-228456'
  tag rid: 'SV-228456r508021_rule'
  tag stig_id: 'DTOO266'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30674r497691_fix'
  tag 'documentable'
  tag legacy: ['V-71233', 'SV-85857']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
