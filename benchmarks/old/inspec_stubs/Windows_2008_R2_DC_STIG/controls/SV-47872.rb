control 'SV-47872' do
  title 'The Deny access to this computer from the network user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny Access from the Network" right defines the accounts that are prevented from logging on from the network.  

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" right, this is a finding:

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny access to this computer from the network" to include the following.

Guests Group'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-44727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1155'
  tag rid: 'SV-47872r1_rule'
  tag stig_id: 'WINUR-000017-DC'
  tag gtitle: 'Deny Access from the Network'
  tag fix_id: 'F-41027r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
