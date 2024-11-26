control 'SV-220410' do
  title 'MarkLogic Server must generate audit records for all privileged activities or other system-level access.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements.

Depending on the capabilities of the DBMS and the design of the database and associated applications, audit logging may be achieved by means of DBMS auditing features, database triggers, other mechanisms, or a combination of these.

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.'
  desc 'check', 'Check MarkLogic audit configuration to verify audit records are generated when privileged actions occur.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If audit enabled field is true but the security-access event is not selected, this is a finding.
6. Under the Audit Restrictions - Outcome section, verify the security-access event for auditing is set to "both". If the setting is not "both", this is a finding.
7. If any roles, URIs, or users are identified in audit restrictions, and not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure MarkLogic to produce audit records when privileged actions occur.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the security-access event for auditing.
6. Enable "both" for the audit restriction under the outcome selection.
7. Ensure no roles, URIs, or users are identified in the audit restrictions, unless documented in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22125r401681_chk'
  tag severity: 'medium'
  tag gid: 'V-220410'
  tag rid: 'SV-220410r622777_rule'
  tag stig_id: 'ML09-00-011300'
  tag gtitle: 'SRG-APP-000504-DB-000354'
  tag fix_id: 'F-22114r401682_fix'
  tag 'documentable'
  tag legacy: ['SV-110169', 'V-101065']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
