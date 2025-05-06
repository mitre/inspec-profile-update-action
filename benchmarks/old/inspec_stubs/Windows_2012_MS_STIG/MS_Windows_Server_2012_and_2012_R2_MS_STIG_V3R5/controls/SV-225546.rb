control 'SV-225546' do
  title 'The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:

Administrators
Authenticated Users

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (V-36661) and required changes frequency (V-36662).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following accounts or groups:

Administrators
Authenticated Users'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27245r471980_chk'
  tag severity: 'medium'
  tag gid: 'V-225546'
  tag rid: 'SV-225546r569185_rule'
  tag stig_id: 'WN12-UR-000002-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27233r471981_fix'
  tag 'documentable'
  tag legacy: ['SV-51499', 'V-26470']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
