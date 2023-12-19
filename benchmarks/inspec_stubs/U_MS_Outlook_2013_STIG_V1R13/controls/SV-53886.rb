control 'SV-53886' do
  title 'The ability to add signatures to email messages must be allowed.'
  desc "Outlook users can create and use signatures in email messages. Users can add signatures to messages manually, and can also configure Outlook to automatically append signatures to new messages, to replies and forwards, or to all three. Signatures typically include details such as the user's name, title, phone numbers, and office location. When an organization has policies that govern the distribution of this kind of information, using signatures might cause some users to inadvertently violate these policies."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013-> Outlook Options -> Mail format "Do not allow signatures for e-mail messages" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\common\\mailsettings

Criteria: If the value DisableSignatures is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Mail format "Do not allow signatures for e-mail messages" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47918r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17673'
  tag rid: 'SV-53886r1_rule'
  tag stig_id: 'DTOO227'
  tag gtitle: 'DTOO227 - Digital Signature handling'
  tag fix_id: 'F-46791r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
