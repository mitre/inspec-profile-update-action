control 'SV-253433' do
  title 'The built-in guest account must be disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled. This account is a known account that exists on all Windows systems and cannot be deleted. This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Guest account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56886r829381_chk'
  tag severity: 'medium'
  tag gid: 'V-253433'
  tag rid: 'SV-253433r829383_rule'
  tag stig_id: 'WN11-SO-000010'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-56836r829382_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
