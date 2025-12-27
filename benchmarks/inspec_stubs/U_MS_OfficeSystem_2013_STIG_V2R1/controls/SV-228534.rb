control 'SV-228534' do
  title 'The first-run prompt to sign into Office365 must be disabled.'
  desc 'Office 365 functionality allows users to provide credentials for accessing Office 365 using either their Microsoft Account, or the user ID assigned by the organization. Access to Office 365 will not be permitted; only locally installed and configured Office 2013 installations will be used. Since the ability to sign into Office 365 will be disabled, this policy, which determines whether the Office First Run comes up on first application boot if not previously viewed, will also be disabled.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> First Run >> "Disable Office First Run on application boot" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\firstrun

Criteria: If the value 'bootedrtm' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> First Run  -> "Disable Office First Run on application boot" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30767r498880_chk'
  tag severity: 'medium'
  tag gid: 'V-228534'
  tag rid: 'SV-228534r508020_rule'
  tag stig_id: 'DTOO404'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30752r498881_fix'
  tag 'documentable'
  tag legacy: ['SV-53193', 'V-40861']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
