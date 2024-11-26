control 'SV-226384' do
  title 'The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on locally" user right defines accounts that are prevented from logging on interactively.  

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" user right, this is a finding:

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following:

Guests Group'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28087r476998_chk'
  tag severity: 'medium'
  tag gid: 'V-226384'
  tag rid: 'SV-226384r794629_rule'
  tag stig_id: 'WN12-UR-000020-DC'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-28075r476999_fix'
  tag 'documentable'
  tag legacy: ['SV-51147', 'V-26485']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
