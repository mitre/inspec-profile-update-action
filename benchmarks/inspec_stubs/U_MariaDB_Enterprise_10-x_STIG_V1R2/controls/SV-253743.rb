control 'SV-253743' do
  title 'When invalid inputs are received, MariaDB must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'As the database administrator, make a small SQL syntax error by running the following:
 
MariaDB> CREAT TABLEincorrect_syntax(id INT) 
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near  CREAT TABLEincorrect_syntax(id INT)  at line 1
  
Now verify the syntax error was logged (change the log file name and part to suit the circumstances):

$ cat $DATADIR/sql_errors.log

2019-09-05 14:31:22 root[root] @ localhost [] ERROR 1064: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near  CREAT TABLEincorrect_syntax(id INT)  at line 1 : CREAT TABLEincorrect_syntax(id INT)

Review security guide to determine how input errors from application to MariaDB are to be handled in general and if any special handling is defined for specific circumstances.

If it does not implement the documented behavior, this is a finding.'
  desc 'fix', "All errors and denials are logged to the sql errorlog. If the sql error log does not exist, install the sql error log plugin as follows:

MariaDB> INSTALL SONAME 'sql_errlog';

The error log should by default be located as sql_errors.log within the data directory (/var/lib/mysql by default)."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57195r841752_chk'
  tag severity: 'medium'
  tag gid: 'V-253743'
  tag rid: 'SV-253743r841754_rule'
  tag stig_id: 'MADB-10-009100'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-57146r841753_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
