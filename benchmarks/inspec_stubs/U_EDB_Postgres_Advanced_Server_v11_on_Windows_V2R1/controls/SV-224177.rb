control 'SV-224177' do
  title 'In the event of a system failure, the DBMS must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc %q(Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.

At all times, Postgres maintains a write ahead log (WAL) in the pg_wal/ subdirectory of the cluster's data directory. The log records every change made to the database's data files. This log exists primarily for crash-safety purposes: if the system crashes, the database can be restored to consistency by “replaying” the log entries made since the last checkpoint. Under the covers, Postgres uses fsync system calls to help ensure that modified database information held in memory is written to disk. To support certain specialized use cases where crash recovery is not as important as system performance, Postgres provides an fsync parameter that can be set to "off" to disable the use of fsync. By default, this parameter is set to "on" and except for the rare use cases should not be set to "off".

To support being able to determine what may have caused a database failure, Postgres inherently logs failures.)
  desc 'check', 'To check whether fsync() has been enabled for the EDB Postgres Advanced Server cluster, connect to the database as a database superuser using psql and execute the following psql command:

 SHOW fsync

If the parameter is set to "off" and this setting has not been documented as approved with justification, this is a finding.'
  desc 'fix', 'To set the fsync parameter to "on", connect to the database as a database superuser using psql and execute the following SQL commands:

 ALTER SYSTEM SET fsync = on;

 SELECT pg_reload_conf();'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25850r495549_chk'
  tag severity: 'medium'
  tag gid: 'V-224177'
  tag rid: 'SV-224177r508023_rule'
  tag stig_id: 'EP11-00-005600'
  tag gtitle: 'SRG-APP-000226-DB-000147'
  tag fix_id: 'F-25838r495550_fix'
  tag 'documentable'
  tag legacy: ['V-100377', 'SV-109481']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
