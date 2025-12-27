control 'SV-226271' do
  title 'The built-in guest account must be disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Guest account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27973r476657_chk'
  tag severity: 'medium'
  tag gid: 'V-226271'
  tag rid: 'SV-226271r569184_rule'
  tag stig_id: 'WN12-SO-000003'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-27961r476658_fix'
  tag 'documentable'
  tag legacy: ['V-1113', 'SV-52855']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
