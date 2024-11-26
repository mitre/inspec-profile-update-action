control 'SV-220396' do
  title 'MarkLogic Server must generate audit records when privileges/permissions are modified.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.'
  desc 'check', 'Check MarkLogic audit configurations to verify that audit records are produced when privileges/permissions/role memberships are modified.

If they are not produced, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If audit enabled field is true but the permission-change, user-role-addition and user-role-removal events are not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when privileges/permissions/role memberships are modified.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the permission-change, user-role-addition, and user-role-removal events for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22111r401639_chk'
  tag severity: 'medium'
  tag gid: 'V-220396'
  tag rid: 'SV-220396r622777_rule'
  tag stig_id: 'ML09-00-009900'
  tag gtitle: 'SRG-APP-000495-DB-000328'
  tag fix_id: 'F-22100r401640_fix'
  tag 'documentable'
  tag legacy: ['SV-110141', 'V-101037']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
