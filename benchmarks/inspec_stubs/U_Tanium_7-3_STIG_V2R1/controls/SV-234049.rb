control 'SV-234049' do
  title 'The Tanium Application Server must be configured to only use Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the System Administrator for the Windows Operation System Active Directory.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Users" tab.

Consult with the Tanium System Administrator to review the documented list of Tanium users.

Compare the list of Tanium users versus the users found in the appropriate Active Directory security groups for the User Roles.

If there are any console users who are listed in the Tanium console that are not found in a synced Active Directory security group, this is a finding.

Alternatively, the ISSO can document the non-synced Active Directory security group users and accept the risk for the users.

If this is the case, this would no longer be a finding.'
  desc 'fix', %q(Consult with the Tanium System Administrator to review the documented list of Tanium users.

Compare the list of Tanium users versus the users found in the appropriate Active Directory security groups for the User Roles.

Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on "Administration".

Select the "Users" tab.

Any users populated manually, select the user's name, and then click on the ""trashcan"" icon at the top of the console to delete this user.

Note: Consult with the Tanium System Administrator before deleting any user accounts to ensure any scheduled actions or other content is reassigned to another user. This will prevent any potential issues arising from the deletion of a user.)
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37234r610647_chk'
  tag severity: 'medium'
  tag gid: 'V-234049'
  tag rid: 'SV-234049r612749_rule'
  tag stig_id: 'TANS-CN-000003'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-37199r610648_fix'
  tag 'documentable'
  tag legacy: ['SV-102171', 'V-92069']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
