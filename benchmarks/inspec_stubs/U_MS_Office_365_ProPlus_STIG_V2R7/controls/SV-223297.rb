control 'SV-223297' do
  title 'Consistent MIME handling must be enabled for all Office 365 ProPlus programs.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the application server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. 

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Consistent Mime Handling is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_mime_handling

If the value for all installed Office programs is set to is REG_DWORD=1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security "Consistent Mime Handling" to "Enabled" and select the check boxes for all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24970r822361_chk'
  tag severity: 'medium'
  tag gid: 'V-223297'
  tag rid: 'SV-223297r822362_rule'
  tag stig_id: 'O365-CO-000015'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-24958r442111_fix'
  tag 'documentable'
  tag legacy: ['SV-108773', 'V-99669']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
