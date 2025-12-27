control 'SV-220413' do
  title 'MarkLogic must be able to generate audit records when successful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.'
  desc 'check', 'Review audit settings to verify objects identified by the application owner, for which access must be audited, are being audited.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Inspect the audit enabled field. A value of false means auditing is not enabled and this is a finding. 
5. If any audit events identified in the System Security Plan are not enabled, this is a finding.
6. If the Audit Restrictions - Outcome is not Both, this is a finding.
7. If any Audit Restriction Inclusions/Exclusions are not documented in the System Security Plan, this is a finding.'
  desc 'fix', 'Configure audit settings to create audit records when the specified access to the specified objects occurs.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to check resides (e.g., Default).
3. Click the Auditing icon on the left tree menu.
4. Set the audit enabled field to true.
5. Enable any audit events identified as required in the System Security Plan (SSP).
6. Set the Audit Restrictions - Outcome to Both.
7. If any Audit Restriction - Inclusions/Exclusions are approved in the SSP, ensure they have been applied.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22128r401690_chk'
  tag severity: 'medium'
  tag gid: 'V-220413'
  tag rid: 'SV-220413r622777_rule'
  tag stig_id: 'ML09-00-011700'
  tag gtitle: 'SRG-APP-000507-DB-000356'
  tag fix_id: 'F-22117r401691_fix'
  tag 'documentable'
  tag legacy: ['SV-110175', 'V-101071']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
