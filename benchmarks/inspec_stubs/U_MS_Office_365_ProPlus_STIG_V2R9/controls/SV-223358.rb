control 'SV-223358' do
  title 'Outlook must be configured to allow retrieving of Certificate Revocation Lists (CRLs) always when online.'
  desc 'This policy setting controls how Outlook retrieves Certificate Revocation Lists to verify the validity of certificates. Certificate revocation lists (CRLs) are lists of digital certificates that have been revoked by their controlling certificate authorities (CAs), typically because the certificates were issued improperly or their associated private keys were compromised. 

If you enable this policy setting, you can choose from three options to govern how Outlook uses CRLs: 
- Use system Default. Outlook relies on the CRL download schedule that is configured for the operating system. 
- When online always retrieve the CRL. This option is the default configuration in Outlook. 
- Never retrieve the CRL. Outlook will not attempt to download the CRL for a certificate, even if it is online. This option can reduce security. 

If you disable or do not configure this policy setting, when Outlook handles a certificate that includes a URL from which a CRL can be downloaded, Outlook will retrieve the CRL from the provided URL if Outlook is online.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Signature Status dialog box >> Retrieving CRLs (Certificate Revocation Lists) is set to "Enabled" "When online always retrieve the CRL".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for usecrlchasing is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Cryptography >> Signature Status dialog box >> Retrieving CRLs (Certificate Revocation Lists) to "Enabled" "When online always retrieve the CRL".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25031r811490_chk'
  tag severity: 'medium'
  tag gid: 'V-223358'
  tag rid: 'SV-223358r879897_rule'
  tag stig_id: 'O365-OU-000013'
  tag gtitle: 'SRG-APP-000605'
  tag fix_id: 'F-25019r442294_fix'
  tag 'documentable'
  tag legacy: ['SV-108895', 'V-99791']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
