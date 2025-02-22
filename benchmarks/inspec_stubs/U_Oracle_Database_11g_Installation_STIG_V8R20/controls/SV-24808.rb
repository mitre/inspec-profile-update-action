control 'SV-24808' do
  title 'DBMS network communications should comply with PPS usage restrictions.'
  desc 'Non-standard network ports, protocol or services configuration or usage could lead to bypass of network perimeter security controls and protections.'
  desc 'check', 'If Oracle Listener, JAVA Listener, Oracle Names and Connection Manager are not running on the local database host server, this check is Not a Finding. 

Review the listener.ora file located by default in the ORACLE_HOME\\network\\admin directory or in the directory specified in the environment variable TNS_ADMIN defined for the listener process or service.  

View the "PORT=" parameter for any protocols defined.

If any do not match an entry in the following list, then confirm that it is not a default or registered port for the service.

View the cman.ora file in the ORACLE_HOME/network/admin directory.

If the file does not exist, the database is not accessed via Oracle Connection Manager and this part of the check is Not a Finding.

View the "PORT=" parameter for any protocols defined.

If any do not match an entry in the following list, then confirm that it is not a default or registered port for the service.

If any non-default or non-registered ports are listed, this is a Finding.

Default Oracle Listener Ports:  1521, 2483, 2484
Default Java Listener Ports:  2481, 2482
Default Oracle Names Listener Port:  1575
Default Connection Manager Ports:  1521, 1830

Registered ports MAY be listed at http://www.iana.org/assignments/port-numbers or in the DoD Ports, Protocols, and Services Category Assurance List (CAL).'
  desc 'fix', 'Specify a default or registered port for TCP/IP protocols in the listener.ora and cman.ora files in the PORT= parameter of the address specification.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15148'
  tag rid: 'SV-24808r1_rule'
  tag stig_id: 'DG0152-ORACLE11'
  tag gtitle: 'DBMS network port, protocol and services (PPS) use'
  tag fix_id: 'F-26398r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
