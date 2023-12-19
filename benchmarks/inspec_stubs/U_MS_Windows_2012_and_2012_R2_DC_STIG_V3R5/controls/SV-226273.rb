control 'SV-226273' do
  title 'The built-in administrator account must be renamed.'
  desc 'The built-in administrator account is a well-known account subject to attack.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Accounts: Rename administrator account" is not set to a value other than "Administrator", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Rename administrator account" to a name other than "Administrator".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27975r476663_chk'
  tag severity: 'medium'
  tag gid: 'V-226273'
  tag rid: 'SV-226273r794581_rule'
  tag stig_id: 'WN12-SO-000005'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27963r476664_fix'
  tag 'documentable'
  tag legacy: ['SV-52857', 'V-1115']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
