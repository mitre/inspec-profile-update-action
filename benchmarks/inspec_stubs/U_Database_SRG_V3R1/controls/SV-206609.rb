control 'SV-206609' do
  title 'When invalid inputs are received, the DBMS must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Review system documentation to determine how input errors are to be handled in general and if any special handling is defined for specific circumstances.

Review the source code for database program objects (stored procedures, functions, triggers) and application source code to identify how the system responds to invalid input.

If it does not implement the documented behavior, this is a finding.'
  desc 'fix', 'Revise and deploy the source code for database program objects (stored procedures, functions, triggers) and application source code, to implement the documented behavior.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6869r291495_chk'
  tag severity: 'medium'
  tag gid: 'V-206609'
  tag rid: 'SV-206609r617447_rule'
  tag stig_id: 'SRG-APP-000447-DB-000393'
  tag gtitle: 'SRG-APP-000447'
  tag fix_id: 'F-6869r291496_fix'
  tag 'documentable'
  tag legacy: ['V-58183', 'SV-72613']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
