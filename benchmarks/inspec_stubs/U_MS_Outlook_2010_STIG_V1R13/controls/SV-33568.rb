control 'SV-33568' do
  title 'Automatic sending  s/Mime receipt requests must be disallowed.'
  desc 'Incoming signed or encrypted messages might include S/MIME receipt requests. S/MIME receipts provide confirmation that messages are received unaltered, and can include information about who opened the message and when it was opened.
By default, when users open messages with attached receipt requests, Outlook prompts them to decide whether to send a receipt to the sender with information about the identity of the user who opened the message and the time it was opened. If Outlook cannot send the receipt, the user is still allowed to open the message.
In some situations, allowing Outlook to automatically send receipt requests could cause sensitive information to be divulged to unauthorized people.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “S/MIME receipt requests behavior” must be  “Enabled (Never send S\\MIME receipts)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value RespondToReceiptRequests is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “S/MIME receipt requests behavior” to “Enabled (Never send S\\MIME receipts)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34030r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17795'
  tag rid: 'SV-33568r1_rule'
  tag stig_id: 'DTOO266 - Outlook'
  tag gtitle: 'DTOO266 - S/Mime receipt requests'
  tag fix_id: 'F-29714r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
