control 'SV-228453' do
  title 'Message formats must be set to use SMime.'
  desc 'This policy setting controls which message encryption formats Outlook can use. Outlook supports three formats for encrypting and signing messages: S/MIME, Exchange, and Fortezza. If you enable this policy setting, you can specify whether Outlook can use S/MIME (the default), Exchange, or Fortezza encryption, or any combination of any of these options. Users will not be able to change this configuration. If you disable or do not configure this policy setting, Outlook only uses S/MIME to encrypt and sign messages. If you disable this policy setting, users will not be able to change this configuration.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Message Formats" is set to "Enabled (S\\MIME)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value MsgFormats is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Message Formats" to "Enabled (S\\MIME)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30686r497681_chk'
  tag severity: 'medium'
  tag gid: 'V-228453'
  tag rid: 'SV-228453r508021_rule'
  tag stig_id: 'DTOO260'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-30671r497682_fix'
  tag 'documentable'
  tag legacy: ['V-71227', 'SV-85851']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
