control 'SV-226382' do
  title 'The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a batch job" user right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.  

The Guests group must be assigned to prevent unauthenticated access.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" user right, this is a finding:

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a batch job" to include the following:

Guests Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28085r476992_chk'
  tag severity: 'medium'
  tag gid: 'V-226382'
  tag rid: 'SV-226382r794627_rule'
  tag stig_id: 'WN12-UR-000018-DC'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-28073r476993_fix'
  tag 'documentable'
  tag legacy: ['V-26483', 'SV-51145']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
