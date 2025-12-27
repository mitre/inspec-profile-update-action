control 'SV-54033' do
  title 'Missing Root Certificates warning must be enforced.'
  desc 'When Outlook accesses a certificate, it validates that it can trust the certificate by examining the root certificate of the issuing CA. If the root certificate can be trusted, then certificates issued by the CA can also be trusted.  If Outlook cannot find the root certificate, it cannot validate that any certificates issued by that CA can be trusted. An attacker may compromise a root certificate and then remove the certificate in an attempt to conceal the attack.  By default, Outlook displays a warning message when a CRL is not available.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography -> Signature Status dialog box "Missing root certificates" is set to "Enabled (Error)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value SigStatusNoTrustDecision is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography -> Signature Status dialog box "Missing root certificates" to "Enabled (Error)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47980r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17756'
  tag rid: 'SV-54033r1_rule'
  tag stig_id: 'DTOO268'
  tag gtitle: 'DTOO268 - Missing Root Certificates'
  tag fix_id: 'F-46918r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
