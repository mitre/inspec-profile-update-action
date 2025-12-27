control 'SV-220383' do
  title 'MarkLogic Server must produce audit records of its enforcement of access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Without auditing the enforcement of access restrictions against changes to configuration, it would be difficult to identify attempted attacks and an audit trail would not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Review the MarkLogic security and audit configurations to verify that audit records are produced when other errors prevent attempts to change the configuration of the MarkLogic Server or database(s).

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field, a value of false means auditing is not enabled, this is a finding. 
5. If the following audit events are not enabled, this is a finding:
- Audit Configuration Change
- Configuration Change
- User Configuration Change
6. If the Audit Restrictions - Outcome is not Both, this is a finding.
7. If any Audit Restriction Inclusions/Exclusions are not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure the MarkLogic to produce audit records when it denies attempts to change the configuration or when other errors prevent attempts to change the configuration of the MarkLogic Server or database(s).

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable the following audit events:
- Audit Configuration Change
- Configuration Change
- User Configuration Change
6. Set the Audit Restrictions - Outcome to Both.
7. If any Audit Restriction - Inclusions/Exclusions are approved in the SSP, ensure they have been applied.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22098r401600_chk'
  tag severity: 'medium'
  tag gid: 'V-220383'
  tag rid: 'SV-220383r855488_rule'
  tag stig_id: 'ML09-00-007900'
  tag gtitle: 'SRG-APP-000381-DB-000361'
  tag fix_id: 'F-22087r401601_fix'
  tag 'documentable'
  tag legacy: ['SV-110115', 'V-101011']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
