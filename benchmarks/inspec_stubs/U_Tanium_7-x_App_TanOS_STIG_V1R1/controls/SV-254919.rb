control 'SV-254919' do
  title 'The Tanium application must restrict the ability of individuals to use information systems to launch organization-defined Denial of Service (DoS) attacks against other information systems.'
  desc 'The Tanium Action Approval feature provides a two-person integrity control mechanism designed to achieve a high-level of security and reduce the possibility of error for critical operations and DoS conditions.

When this feature is enabled, an action configured by one Tanium console user will require a second Tanium console user with a role of Action Approver (or higher) to approve the action before it is deployed to targeted computers.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. In the "Filter items" search box, type "require_action_approval".

5. Click "Enter".

If no results are returned, this is a finding.

If results are returned for "require_action_approval", but the value is not "1", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration," select "Platform Settings".

4. Click "Create Setting".

5. Select "Server" for "Setting Type".

5. In "Create Platform Setting" dialog box, enter "require_action_approval" does not exist: Flag" for " Name".

6. Select the "Numeric" radio button for "Value Type".

7. Enter "1" for "Value".

8. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58532r867655_chk'
  tag severity: 'medium'
  tag gid: 'V-254919'
  tag rid: 'SV-254919r867657_rule'
  tag stig_id: 'TANS-AP-000630'
  tag gtitle: 'SRG-APP-000246'
  tag fix_id: 'F-58476r867656_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
