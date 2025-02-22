control 'SV-220399' do
  title 'MarkLogic Server must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Check MarkLogic audit configurations to verify that audit records are produced when the system denies attempts or other errors prevent attempts to modify security objects.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If audit enabled field is true but the security-access event are not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions, and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when it denies attempts to modify security objects, or other errors prevent attempts to modify security objects

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22114r401648_chk'
  tag severity: 'medium'
  tag gid: 'V-220399'
  tag rid: 'SV-220399r622777_rule'
  tag stig_id: 'ML09-00-010200'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-22103r401649_fix'
  tag 'documentable'
  tag legacy: ['SV-110147', 'V-101043']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
