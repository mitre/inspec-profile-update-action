control 'SV-213635' do
  title 'When invalid inputs are received, the EDB Postgres Advanced Server must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or if sqlprotect.list_protected_users does not exist (meaning SQL/Protect is not installed), and an alternative means of reviewing for vulnerable code is not in use, this is a finding.'
  desc 'fix', 'Install and configure SQL/Protect as documented here: 

http://www.enterprisedb.com/docs/en/9.5/eeguide/Postgres_Plus_Enterprise_Edition_Guide.1.072.html#

Alternatively, implement, document, and maintain another method of checking for the validity of inputs.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14857r290217_chk'
  tag severity: 'medium'
  tag gid: 'V-213635'
  tag rid: 'SV-213635r508024_rule'
  tag stig_id: 'PPS9-00-009700'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-14855r290218_fix'
  tag 'documentable'
  tag legacy: ['V-69023', 'SV-83627']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
