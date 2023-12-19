control 'SV-81901' do
  title 'When invalid inputs are received, SQL Server must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Review system documentation to determine how input errors are to be handled in general and if any special handling is defined for specific circumstances.

Review the source code for database program objects (stored procedures, functions, triggers) and application source code to identify how the system responds to invalid input.

If it does not implement the documented behavior, this is a finding.'
  desc 'fix', 'Revise and deploy the source code for database program objects (stored procedures, functions, triggers) and application source code, to implement the documented behavior.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67411'
  tag rid: 'SV-81901r2_rule'
  tag stig_id: 'SQL4-00-035200'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-73525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
