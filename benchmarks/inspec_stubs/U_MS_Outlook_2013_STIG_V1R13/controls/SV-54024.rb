control 'SV-54024' do
  title 'Warning about invalid signatures must be enforced.'
  desc 'If users open email messages that include invalid digital signatures, Outlook displays a warning dialog box. Users can decide whether they want to be warned about invalid signatures in the future. If users are not notified about invalid signatures, they might be prevented from detecting a fraudulent signature sent by a malicious person.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Signature Warning" is "Enabled (Always warn about invalid signatures)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value WarnAboutInvalid is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Signature Warning" to "Enabled (Always warn about invalid signatures)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17803'
  tag rid: 'SV-54024r1_rule'
  tag stig_id: 'DTOO265'
  tag gtitle: 'DTOO265 - Signature Warnings'
  tag fix_id: 'F-46910r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
