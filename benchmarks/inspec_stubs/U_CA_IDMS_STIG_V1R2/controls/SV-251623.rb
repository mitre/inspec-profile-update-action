control 'SV-251623' do
  title 'CA IDMS and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.'
  desc 'When the use of dynamic SQL is necessary, the code should be written so that the invalid data can be found and the appropriate action taken.'
  desc 'check', 'If dynamic code execution is used and identified user input is not validity checked user input, this is a finding. 

If SQL-defined tables, DISPLAY TABLE <schema-name>.<table-name> . If there is not a CHECK for the columns and accompanying accepted values, this is a finding.

If network-defined records, DISPLAY SCHEMA or DISPLAY RECORD. If there is no CALL to a procedure BEFORE STORE and BEFORE MODIFY, this is a finding.

If the procedure does not validate the non-exempt columns, this is a finding.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.'
  desc 'fix', 'For SQL-defined tables, ALTER TABLE <schema-name>.<table-name> ADD CHECK (search-condition).

For network-defined records, MODIFY <record-name> CALL procedure BEFORE STORE/MODIFY. Create or update procedure to validate provided record field values.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55058r807734_chk'
  tag severity: 'medium'
  tag gid: 'V-251623'
  tag rid: 'SV-251623r807736_rule'
  tag stig_id: 'IDMS-DB-000520'
  tag gtitle: 'SRG-APP-000251-DB-000392'
  tag fix_id: 'F-55012r807735_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
