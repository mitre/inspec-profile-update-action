control 'SV-87321' do
  title 'When invalid inputs are received, the Cassandra Server must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'Review the Cassandra Server to ensure that it behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

Open the "cqlsh" prompt in the Cassandra Server and type "DESCRIBE KEYSPACES;". Type "DESCRIBE <keyspace name>" for all the keyspace names that have been displayed as output for the first command. Review keyspaces content.

Open the console to the server that Cassandra DB is hosted at and type: "find / | grep "logback.xml"". Open "logback.xml" file and review "level" parameter value under <root />.

If level is not set to "ALL", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to behave in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.

Modify tables by adding constraints (CREATE TRIGGER IF NOT EXISTS <trigger_name> ON <table name>, where TRIGGER triggered validation event).

Open console to the server, Cassandra DB is hosted at, and type: "find / | grep "logback.xml"". Open "logback.xml" file and set "level" parameter value under <root /> to "ALL".'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72689'
  tag rid: 'SV-87321r1_rule'
  tag stig_id: 'VROM-CS-000250'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-79093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
