control 'SV-33598' do
  title 'Always warn on untrusted macros must be enforced.'
  desc "To protect users from dangerous code, the Outlook default configuration disables all macros that are not trusted, including unsigned macros, macros with expired or invalid signatures, and macros with valid signatures from publishers who are not on users' Trusted Publishers lists. The default configuration also allows macros that are signed by trusted publishers to run automatically without notifying users, which could allow dangerous code to run."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Trust Center “Security setting for macros” must be “Enabled (Always warn)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value Level is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Trust Center “Security setting for macros” to “Enabled (Always warn)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34060r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17798'
  tag rid: 'SV-33598r1_rule'
  tag stig_id: 'DTOO276 - Outlook'
  tag gtitle: 'DTOO276 - Security settings for macros'
  tag fix_id: 'F-29740r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
