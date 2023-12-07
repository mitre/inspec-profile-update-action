control 'SV-33376' do
  title 'The Access this computer from the network user right must only be assigned to the Administrators and Authenticated Users groups on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.

Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:

Administrators
Authenticated Users

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length and required changes frequency (V-14271).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following accounts or groups:

Administrators
Authenticated Users'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-81117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26470'
  tag rid: 'SV-33376r4_rule'
  tag stig_id: 'WINUR-000002-MS'
  tag gtitle: 'Access this computer from the network'
  tag fix_id: 'F-88193r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
