control 'SV-54005' do
  title 'Run in FIPS compliant mode must be enforced.'
  desc "Outlook can run in a mode that complies with Federal Information Processing Standards (FIPS), a set of standards published by the National Institute of Standards and Technology (NIST) for use by non-military United States government agencies and by government contractors.
By default, Outlook does not run in FIPS-compliant mode. Organizations that do business with the U.S. government but do not run Outlook in FIPS-compliant mode risk violating the government's rules regarding the handling of sensitive information."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Run in FIPS compliant mode" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value FIPSMode is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Run in FIPS compliant mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17787'
  tag rid: 'SV-54005r1_rule'
  tag stig_id: 'DTOO262'
  tag gtitle: 'DTOO262 - FIPS compliant mode'
  tag fix_id: 'F-46894r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
