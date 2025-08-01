control 'SV-251649' do
  title 'IDMS must check for invalid data and behave in a predictable manner when encountered.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'If data inputs are specifically identified by the organization as exempt from validity checks, this is not applicable.

If SQL-defined tables, DISPLAY TABLE <schema-name>.<table-name> . If there is not a CHECK for the columns and accompanying accepted values, this is a finding.

If network-defined records, DISPLAY SCHEMA or DISPLAY RECORD. If there is no CALL to a procedure BEFORE STORE and BEFORE MODIFY, this is a finding. If the procedure does not validate the non-exempt columns, this is a finding.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.

Review the source code for checks, procedures, and edits to identify how the system responds to invalid input. If it does not implement the documented behavior, this is a finding.'
  desc 'fix', 'Revise and deploy source code changes for checks, procedures, and edits to implement the documented behavior. 

For SQL-defined tables, ALTER TABLE <schema-name>.<table-name> ADD CHECK (search-condition).

For network-defined records, MODIFY <record-name> CALL procedure BEFORE STORE/MODIFY. Create or update procedure to validate provided record field values.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55084r807812_chk'
  tag severity: 'medium'
  tag gid: 'V-251649'
  tag rid: 'SV-251649r808356_rule'
  tag stig_id: 'IDMS-DB-000880'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-55038r808355_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
