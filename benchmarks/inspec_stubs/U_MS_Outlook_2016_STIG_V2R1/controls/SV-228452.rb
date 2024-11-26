control 'SV-228452' do
  title 'S/Mime interoperability with external clients for message handling must be configured.'
  desc 'This policy setting controls whether Outlook decodes encrypted messages itself or passes them to an external program for processing. If you enable this policy setting, you can choose from three options for configuring external S/MIME clients:- Handle internally. Outlook decrypts all S/MIME messages itself.- Handle externally. Outlook hands all S/MIME messages off to the configured external program.- Handle if possible. Outlook attempts to decrypt all S/MIME messages itself. If it cannot decrypt a message, Outlook hands the message off to the configured external program. This option is the default configuration. If you disable or do not configure this policy setting, the behavior is the equivalent of selecting Enabled: Handle if possible.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "S/MIME interoperability with external clients" is set to "Enabled (Handle internally)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value ExternalSMime is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "S/MIME interoperability with external clients" to "Enabled (Handle internally)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30685r497678_chk'
  tag severity: 'medium'
  tag gid: 'V-228452'
  tag rid: 'SV-228452r508021_rule'
  tag stig_id: 'DTOO257'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-30670r497679_fix'
  tag 'documentable'
  tag legacy: ['V-71195', 'SV-85819']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
