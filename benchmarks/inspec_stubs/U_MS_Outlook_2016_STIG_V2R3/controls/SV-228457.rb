control 'SV-228457' do
  title 'Retrieving of CRL data must be set for online action.'
  desc 'This policy setting controls how Outlook retrieves Certificate Revocation Lists to verify the validity of certificates.Certificate revocation lists (CRLs) are lists of digital certificates that have been revoked by their controlling certificate authorities (CAs), typically because the certificates were issued improperly or their associated private keys were compromised. If you enable this policy setting, you can choose from three options to govern how Outlook uses CRLs: - Use system Default. Outlook relies on the CRL download schedule that is configured for the operating system. - When online always retrieve the CRL. This option is the default configuration in Outlook. - Never retrieve the CRL. Outlook will not attempt to download the CRL for a certificate, even if it is online. This option can reduce security. If you disable or do not configure this policy setting, when Outlook handles a certificate that includes a URL from which a CRL can be downloaded, Outlook will retrieve the CRL from the provided URL if Outlook is online.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography -> Signature Status dialog box "Retrieving CRLs (Certificate Revocation Lists)" is set to "Enabled (When online always retrieve the CRL)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value UseCRLChasing is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography -> Signature Status dialog box "Retrieving CRLs (Certificate Revocation Lists)" to "Enabled (When online always retrieve the CRL)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30690r497693_chk'
  tag severity: 'medium'
  tag gid: 'V-228457'
  tag rid: 'SV-228457r508021_rule'
  tag stig_id: 'DTOO267'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-30675r497840_fix'
  tag 'documentable'
  tag legacy: ['SV-85859', 'V-71235']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
