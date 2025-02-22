control 'SV-225562' do
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed.  This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27261r472028_chk'
  tag severity: 'medium'
  tag gid: 'V-225562'
  tag rid: 'SV-225562r569185_rule'
  tag stig_id: 'WN12-UR-000022-MS'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27249r472029_fix'
  tag 'documentable'
  tag legacy: ['SV-51500', 'V-26487']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
