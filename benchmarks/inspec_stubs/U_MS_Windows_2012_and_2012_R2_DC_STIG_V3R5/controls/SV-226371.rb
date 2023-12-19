control 'SV-226371' do
  title 'Unauthorized accounts must not have the Access this computer from the network user right on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" right may access resources on the system and should be limited to those requiring it.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding:

Administrators
Authenticated Users
Enterprise Domain Controllers'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Access this computer from the network" to only include the following accounts or groups:

Administrators
Authenticated Users
Enterprise Domain Controllers

Severity Override Guidance: If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
- Vendor documentation must support the requirement for having the user right.
- The requirement must be documented with the ISSO.
- The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28073r476957_chk'
  tag severity: 'medium'
  tag gid: 'V-226371'
  tag rid: 'SV-226371r794624_rule'
  tag stig_id: 'WN12-UR-000002-DC'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-28061r794623_fix'
  tag 'documentable'
  tag legacy: ['V-26470', 'SV-51142']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
