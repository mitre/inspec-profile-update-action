control 'SV-225451' do
  title 'The built-in guest account must be renamed.'
  desc 'The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options.

If the value for "Accounts: Rename guest account" is not set to a value other than "Guest", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Rename guest account" to a name other than "Guest".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27150r471695_chk'
  tag severity: 'medium'
  tag gid: 'V-225451'
  tag rid: 'SV-225451r569185_rule'
  tag stig_id: 'WN12-SO-000006'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27138r471696_fix'
  tag 'documentable'
  tag legacy: ['SV-52856', 'V-1114']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
