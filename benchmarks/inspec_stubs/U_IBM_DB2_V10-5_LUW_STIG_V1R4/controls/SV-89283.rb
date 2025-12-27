control 'SV-89283' do
  title 'When invalid inputs are received, DB2 must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for the review of applications, which will require collaboration with the application developers. It is recognized that in many cases the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue is addressed, and must document what has been discovered.'
  desc 'check', 'Review system documentation to determine how input errors are to be handled in general and if any special handling is defined for specific circumstances.

Review the source code for database program objects (stored procedures, functions, triggers) and application source code to identify how the system responds to invalid input.

If it does not implement the documented behavior, this is a finding.'
  desc 'fix', 'Revise and deploy the source code for database program objects (stored procedures, functions, triggers) and application source code, to implement the documented behavior.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74495r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74609'
  tag rid: 'SV-89283r1_rule'
  tag stig_id: 'DB2X-00-009300'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-81209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
