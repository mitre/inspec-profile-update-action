control 'SV-235195' do
  title 'When invalid inputs are received, the MySQL Database Server 8.0 must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Review the MySQL Server to ensure it behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

To determine if table check constraints that have been put in place:
SELECT * FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS;

If input validation is required beyond those enforced by the datatype and no constraints exist for data input, this is a finding.'
  desc 'fix', 'Configure the MySQL Server to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

To validate data at the database table level modify tables by adding constraints CHECK constraint is a type of integrity constraint in SQL within the create or alter table statement.

[CONSTRAINT [symbol]] CHECK (expr) [[NOT] ENFORCED]
For example
CREATE TABLE checker (i tinyint, CONSTRAINT i_must_be_between_7_and_12 CHECK (i BETWEEN 7 AND 12 ) ); 
Adding a constraint to an existing table 

ALTER TABLE <table_name> 
           ADD [CONSTRAINT [symbol]] CHECK (condition) [[NOT] ENFORCED]'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38414r623705_chk'
  tag severity: 'medium'
  tag gid: 'V-235195'
  tag rid: 'SV-235195r879818_rule'
  tag stig_id: 'MYS8-00-012500'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-38377r623706_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
