control 'SV-228537' do
  title 'The prompt to save to OneDrive (formerly SkyDrive) must be disabled.'
  desc 'OneDrive (formerly SkyDrive) is a cloud based storage feature that introduces the capability for users to save documents to locations outside of protected enclaves. This feature introduces the risk that FOUO and PII data, as well as other DoD protected data, may be inadvertently stored in a nonsecure location.  This setting, which will prompt the user to sign in to OneDrive while performing a file save operation, must be disabled.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Miscellaneous .> "Show OneDrive Sign In" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\general

If the value 'SkyDriveSignInOption' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Miscellaneous -> "Show OneDrive Sign In" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30770r498889_chk'
  tag severity: 'medium'
  tag gid: 'V-228537'
  tag rid: 'SV-228537r508020_rule'
  tag stig_id: 'DTOO407'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30755r498890_fix'
  tag 'documentable'
  tag legacy: ['SV-53196', 'V-40864']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
