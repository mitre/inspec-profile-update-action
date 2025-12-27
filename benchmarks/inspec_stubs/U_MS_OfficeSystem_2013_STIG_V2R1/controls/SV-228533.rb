control 'SV-228533' do
  title 'The video informing a user about signing into Office365 must be disabled.'
  desc 'Office 365 is a subscription-based service which offers access to various Microsoft Office applications.  Access to Office 365 will not be permitted; only locally installed and configured Office 2013 installations will be used. Since the ability to sign into Office 365 will be disabled, this policy, which determines whether a video about signing into Office365 is played when Office first runs, will also be disabled.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> First Run >> "Disable First Run Movie" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\firstrun

Criteria: If the value 'disablemovie' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> First Run -> "Disable First Run Movie" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30766r498877_chk'
  tag severity: 'medium'
  tag gid: 'V-228533'
  tag rid: 'SV-228533r508020_rule'
  tag stig_id: 'DTOO403'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30751r498878_fix'
  tag 'documentable'
  tag legacy: ['SV-53192', 'V-40860']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
