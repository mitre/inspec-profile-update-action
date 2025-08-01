control 'SV-39581' do
  title 'Unauthorized accounts will not have the "Access this computer from the network" user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Access this computer from the network" right may access resources on the system and should be limited to those requiring it.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the “Access this computer from the network” right, this is a finding:

Administrators
Authenticated Users
Enterprise Domain Controllers'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Access this computer from the network" as defined in the Check section.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-38496r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26470'
  tag rid: 'SV-39581r1_rule'
  tag stig_id: 'WINUR-000002-AD'
  tag gtitle: 'Access this computer from the network'
  tag fix_id: 'F-29549r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
