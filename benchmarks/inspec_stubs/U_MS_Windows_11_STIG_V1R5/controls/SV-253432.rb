control 'SV-253432' do
  title 'The built-in administrator account must be disabled.'
  desc 'The built-in administrator account is a well-known account subject to attack. It also provides no accountability to individual administrators on a system. It must be disabled to prevent its use.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Administrator account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56885r829378_chk'
  tag severity: 'medium'
  tag gid: 'V-253432'
  tag rid: 'SV-253432r829380_rule'
  tag stig_id: 'WN11-SO-000005'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-56835r829379_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
