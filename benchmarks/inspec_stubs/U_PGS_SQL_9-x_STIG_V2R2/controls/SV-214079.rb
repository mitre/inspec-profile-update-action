control 'SV-214079' do
  title 'When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.'
  desc 'check', 'As the database administrator (shown here as "postgres"), make a small SQL syntax error in psql by running the following: 

$ sudo su - postgres 
$ psql -c "CREAT TABLEincorrect_syntax(id INT)" 
ERROR: syntax error at or near "CREAT" 

Note: The following instructions use the PGVER environment variable. See supplementary content APPENDIX-H for instructions on configuring PGVER.

Now, as the database administrator (shown here as "postgres"), verify the syntax error was logged (change the log file name and part to suit the circumstances): 

$ sudo su - postgres 
$ cat ~/${PGVER?}/data/pg_log/postgresql-Wed.log 
2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dERROR: syntax error at or near "CREAT" at character 1 
2016-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dSTATEMENT: CREAT TABLE incorrect_syntax(id INT); 

Review system documentation to determine how input errors from application to PostgreSQL are to be handled in general and if any special handling is defined for specific circumstances. 

If it does not implement the documented behavior, this is a finding.'
  desc 'fix', 'Enable logging.

To ensure that logging is enabled, review supplementary content APPENDIX-C for instructions on enabling logging.

All errors and denials are logged if logging is enabled.'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15295r360868_chk'
  tag severity: 'medium'
  tag gid: 'V-214079'
  tag rid: 'SV-214079r508027_rule'
  tag stig_id: 'PGS9-00-003700'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-15293r360869_fix'
  tag 'documentable'
  tag legacy: ['SV-87559', 'V-72907']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
