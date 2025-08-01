control 'SV-33880' do
  title 'Retrieving of CRL data must be set for online action.'
  desc 'This policy setting controls how Outlook retrieves Certificate Revocation Lists to verify the validity of certificates.  Certificate revocation lists (CRLs) are lists of digital certificates that have been revoked by their controlling certificate authorities (CAs), typically because the certificates were issued improperly or their associated private keys were compromised.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography -> Signature Status dialog box “Retrieving CRLs (Certificate Revocation Lists)” must be “Enabled (When online always retrieve the CRL)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value UseCRLChasing is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography -> Signature Status dialog box “Retrieving CRLs (Certificate Revocation Lists)” to “Enabled (When online always retrieve the CRL)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17778'
  tag rid: 'SV-33880r1_rule'
  tag stig_id: 'DTOO267 - Outlook'
  tag gtitle: 'DTOO267 - Retrieving CRLs - Outlook'
  tag fix_id: 'F-29721r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
