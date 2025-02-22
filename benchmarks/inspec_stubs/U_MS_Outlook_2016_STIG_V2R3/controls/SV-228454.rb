control 'SV-228454' do
  title 'Run in FIPS compliant mode must be enforced.'
  desc "This policy setting controls whether Outlook is required to use FIPS-compliant algorithms when signing and encrypting messages.  Outlook can run in a mode that complies with Federal Information Processing Standards (FIPS), a set of standards published by the National Institute of Standards and Technology (NIST) for use by non-military United States government agencies and by government contractors. If you enable this policy setting, Outlook runs in a mode that complies with the FIPS 140-1 standard for cryptographic modules. This mode requires the use of the SHA-1 algorithm for signing and 3DES for encryption. If you disable or do not configure this policy setting, Outlook does not run in FIPS-compliant mode. Organizations that do business with the United States government but do not run Outlook in FIPS-compliant mode risk violating the U.S. government's rules regarding the handling of sensitive information.For more information about FIPS, see FIPS - General Information at http://www.itl.nist.gov/fipspubs/geninfo.htm

FIPS mode in Windows enforces 3DES, AES 256/192/128, SHA1, and SHA 512/384/256. The 3DES and SHA1 modules are FIPS 140 certified. FIPS mode restricts Outlook to a very short list of SMIME capabilities. Almost all SMIME algorithms are FIPS certified on Windows. Reference https://docs.microsoft.com/en-us/windows/security/threat-protection/fips-140-validation#microsoft-fips-140-2-validated-cryptographic-modules to double check that the SMIME capabilities used and specified in certificates are FIPS certified."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Run in FIPS compliant mode" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value FIPSMode is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Run in FIPS compliant mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30687r497684_chk'
  tag severity: 'medium'
  tag gid: 'V-228454'
  tag rid: 'SV-228454r559729_rule'
  tag stig_id: 'DTOO262'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-30672r497685_fix'
  tag 'documentable'
  tag legacy: ['SV-85853', 'V-71229']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
