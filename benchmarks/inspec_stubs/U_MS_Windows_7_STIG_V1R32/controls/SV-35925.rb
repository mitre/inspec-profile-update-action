control 'SV-35925' do
  title 'The Access this computer from the network user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" right, this is a finding:

Administrators

If a domain application account such as for a management tool requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account, managed at the domain level, must meet requirements for application account passwords, such as length and frequency of changes as defined in the Windows server STIGs.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-78087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26470'
  tag rid: 'SV-35925r3_rule'
  tag stig_id: 'WINUR-000002'
  tag gtitle: 'Access this computer from the network'
  tag fix_id: 'F-65555r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
