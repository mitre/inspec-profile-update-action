control 'SV-54003' do
  title 'S/Mime interoperability with external clients for message handling must be configured.'
  desc 'In some situations, administrators might wish to use an external program, such as an add-in, to handle S/MIME message decryption. If your organization works with encrypted messages that the decryption functionality in Outlook cannot handle appropriately, this setting can be used to configure Outlook to hand S/MIME messages off to an external program for decryption. If no external program has been authorized however, misconfiguring this setting could allow unauthorized and potentially dangerous programs to handle encrypted messages, which could compromise security.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "S/MIME interoperability with external clients" is set to "Enabled (Handle internally)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value ExternalSMime is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "S/MIME interoperability with external clients" to "Enabled (Handle internally)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17790'
  tag rid: 'SV-54003r1_rule'
  tag stig_id: 'DTOO257'
  tag gtitle: 'DTOO257 - No S/Mime interop w/ external clients'
  tag fix_id: 'F-46892r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
