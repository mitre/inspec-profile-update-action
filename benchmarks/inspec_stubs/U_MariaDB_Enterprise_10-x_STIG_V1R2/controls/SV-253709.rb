control 'SV-253709' do
  title 'In the event of a system failure, MariaDB must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Since it is usually not possible to test this capability in a production environment, systems must either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.

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
  tag check_id: 'C-57161r841650_chk'
  tag severity: 'medium'
  tag gid: 'V-253709'
  tag rid: 'SV-253709r841652_rule'
  tag stig_id: 'MADB-10-005100'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-57112r841651_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
