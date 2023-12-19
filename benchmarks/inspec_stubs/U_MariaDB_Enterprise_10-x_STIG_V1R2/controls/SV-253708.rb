control 'SV-253708' do
  title 'MariaDB must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. 

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Systems that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state data also facilitates system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

MariaDB must fail to a known consistent state. Transactions must be successfully completed or rolled back.

In general, security mechanisms must be designed so that a failure will follow the same execution path as disallowing the operation. For example, application security methods, such as isAuthorized(), isAuthenticated(), and validate(), must all return false if there is an exception during processing. If security controls can throw exceptions, they must be very clear about exactly what that condition means. 

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.

MariaDB is a fully functional ACID RDBMS with persistent storage, logs, rollback, recovery, and backup procedures. InnoDB is the default storage engine for MariaDB and all uncommitted transactions are rolled back upon restart from a failure. The process is automatic and all incomplete transactions will be rolled back to a consistent state to guarantee consistency. Users can also conduct a recovery to a point in time if needed.'
  desc 'check', %q(Verify InnoDB logging is configured. 

As the database administrator, verify the following settings: 

Note: If no specific directory is given before the filename, the files are stored in DATADIR.

MariaDB> SHOW GLOBAL VARIABLES LIKE 'log_bin';

If value is "OFF", this is a finding.)
  desc 'fix', 'If value of log_bin is "OFF", modify the MariaDB configuration file. This can be found in /etc/my.cnf.d/.

Optionally specify the location of the binary logs by specifying the full path for the binary logs. 
 
[mariadb]
log_bin=mariadb_bin'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57160r841647_chk'
  tag severity: 'medium'
  tag gid: 'V-253708'
  tag rid: 'SV-253708r841649_rule'
  tag stig_id: 'MADB-10-005000'
  tag gtitle: 'SRG-APP-000225-DB-000153'
  tag fix_id: 'F-57111r841648_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
