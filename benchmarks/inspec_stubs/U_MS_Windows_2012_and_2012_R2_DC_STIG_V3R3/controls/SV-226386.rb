control 'SV-226386' do
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed.  This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Enable computer and user accounts to be trusted for delegation" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28089r477004_chk'
  tag severity: 'medium'
  tag gid: 'V-226386'
  tag rid: 'SV-226386r794658_rule'
  tag stig_id: 'WN12-UR-000022-DC'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28077r477005_fix'
  tag 'documentable'
  tag legacy: ['SV-51149', 'V-26487']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
