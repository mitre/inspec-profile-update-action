control 'SV-33504' do
  title 'Digital signatures must be allowed.'
  desc "Outlook users can create and use signatures in e-mail messages. Users can add signatures to messages manually, and can also configure Outlook to automatically append signatures to new messages, to replies and forwards, or to all three. Signatures typically include details such as the user's name, title, phone numbers, and office location. If your organization has policies that govern the distribution of this kind of information, using signatures might cause some users to inadvertently violate these policies."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010-> Outlook Options -> Mail format “Do not allow signatures for e-mail messages” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\mailsettings

Criteria: If the value DisableSignatures is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010-> Outlook Options -> Mail format “Do not allow signatures for e-mail messages” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33988r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17673'
  tag rid: 'SV-33504r1_rule'
  tag stig_id: 'DTOO227 - Outlook'
  tag gtitle: 'DTOO227 - Digital Signature handling'
  tag fix_id: 'F-29677r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
