control 'SV-220397' do
  title 'MarkLogic Server must generate audit records when unsuccessful attempts to modify privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Check MarkLogic audit configurations to verify that audit records are produced when attempts to modify privileges/permissions/role memberships are denied.

If they are not produced, this is a finding.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means auditing is not enabled, this is a finding. 
5. If audit enabled field is true but the permission-change, user-role-addition, and user-role-removal events are not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions, and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when attempts to modify privileges/permissions/role memberships are denied.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the permission-change, user-role-addition, and user-role-removal events for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22112r401642_chk'
  tag severity: 'medium'
  tag gid: 'V-220397'
  tag rid: 'SV-220397r622777_rule'
  tag stig_id: 'ML09-00-010000'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-22101r401643_fix'
  tag 'documentable'
  tag legacy: ['SV-110143', 'V-101039']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
