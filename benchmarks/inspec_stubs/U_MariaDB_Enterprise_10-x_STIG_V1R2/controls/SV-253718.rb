control 'SV-253718' do
  title 'MariaDB must provide logout functionality to allow the user to manually terminate a session initiated by that user.'
  desc "If a user cannot explicitly end a DBMS session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

Such logout may be explicit or implicit. Examples of explicit are clicking on a Log Out link or button in the application window; clicking the Windows Start button and selecting Log Out or Shut Down. Examples of implicit logout are closing the application's (main) window and powering off the workstation without invoking the OS shutdown. 

Both the explicit and implicit logouts must be detected by the DBMS.

In all cases, the DBMS must ensure that the user's DBMS session and all processes owned by the session are terminated. 

This should not, however, interfere with batch processes/jobs initiated by the user during his/her online session; these should be permitted to run to completion.

As a good programming practice, all applications should close the database connection when they finish using the resource. MariaDB will close the session when the connection is closed and release all resources associated with the session. If the connection cannot be closed, MariaDB has the five global variables to allow timeouts to occur and automatically close the connection and release all associated resources."
  desc 'check', "MariaDB has five global variables which can be set so that connections will be closed after a certain period of inactivity. Check the values for these variables and verify they correspond to security procedures defined: 

MariaDB> SHOW GLOBAL VARIABLES LIKE '%timeout%'; 
 
interactive_timeout  - Time in seconds that the server waits for an interactive connection (one that connects with the mysql_real_connect() CLIENT_INTERACTIVE option) to become active before closing it. See also wait_timeout.

wait_timeout - Time in seconds that the server waits for a connection to become active before closing it. The session value is initialized when a thread starts up from either the global value, if the connection is noninteractive, or from the interactive_timeout value, if the connection is interactive.

In situations where transactions may be started, but not committed or rolled back, more granular control and a shorter timeout may be desirable so as to avoid locks being held for too long.

idle_transaction_timeout
idle_write_transaction_timeout
idle_readonly_transaction_timeout

Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the security procedures require server-side session termination within a specified amount of time but MariaDB is not configured accordingly, this is a finding."
  desc 'fix', 'As an authorized user locate the session to be terminated and terminate that session.

To locate a session and terminate the session follow the following steps:

1. Connect to the MariaDB database using an authorized user:

mariadb -u admin_user -p 

2. At the MariaDB prompt run either of the following commands:

MariaDB> SHOW PROCESSLIST;
MariaDB> SELECT id, user, host, db, command, time, state, info, progress FROM information_schema.processlist;

3. Identify the session to be terminated and issue kill process number from display. (**This will kill the session.**) Example: 

MariaDB> KILL 192;

4. A kill query process number can be issued from display. (**This will kill the active query but leave the session active for run-away queries. **)

Configure MariaDB to automatically terminate a user session based on security procedures requirements regarding conditions or trigger events that require session termination.
 
To change the values of the following timeout variables to conform to organization-defined values for triggering conditions or events requiring session termination, select the appropriate variable to change as the database administrator. 
 
As the administrator locate the MariaDB Enterprise Server configuration file to change. For Centos, RedHat, and similar distributions this will be in /etc/my.cnf.d/.

In the [mariadb] section add the lines:

interactive_timeout = value
wait_timeout = value
idle_transaction_timeout = value
idle_write_transaction_timeout = value
idle_readonly_transaction_timeout = value

Where value is in seconds and corresponds to the company defined value. Restart MariaDB Enterprise Server for these changes to take effect.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57170r841677_chk'
  tag severity: 'medium'
  tag gid: 'V-253718'
  tag rid: 'SV-253718r841679_rule'
  tag stig_id: 'MADB-10-006300'
  tag gtitle: 'SRG-APP-000296-DB-000306'
  tag fix_id: 'F-57121r841678_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
