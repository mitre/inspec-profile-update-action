control 'SV-253717' do
  title "MariaDB must automatically terminate a user's session after organization-defined conditions or trigger events requiring session disconnect."
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance.

As a good programming practice, all applications should close the database connection when they finish using the resource. MariaDB will close the session when the connection is closed and release all resources associated with the session. If the connection is not closed, MariaDB has the five global variables to allow timeouts to occur and automatically close the connection and release all associated resources."
  desc 'check', "MariaDB has five global variables that can be set so that connections will be closed after a certain period of inactivity. Check the values for these variables and verify they correspond to security procedures defined: 

MariaDB> SHOW GLOBAL VARIABLES LIKE '%timeout%'; 
 
interactive_timeout  - Time in seconds that the server waits for an interactive connection (one that connects with the mysql_real_connect() CLIENT_INTERACTIVE option) to become active before closing it. See also wait_timeout.

wait_timeout - Time in seconds that the server waits for a connection to become active before closing it. The session value is initialized when a thread starts up from either the global value, if the connection is noninteractive, or from the interactive_timeout value, if the connection is interactive.

In situations where transactions may be started, but not committed or rolled back, more granular control and a shorter timeout may be desirable so as to avoid locks being held for too long.

idle_transaction_timeout
idle_write_transaction_timeout
idle_readonly_transaction_timeout

Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the security procedures require server-side session termination within a specified amount of time but MariaDB is not configured accordingly, this is a finding."
  desc 'fix', "Configure MariaDB to automatically terminate a user's session based on security procedures requirements regarding conditions or trigger events that require session termination.
 
To change the values of the following timeout variables to conform to organization-defined values for triggering conditions or events requiring session termination select the appropriate variable to change and as the database administrator. 
 
As the administrator locate the MariaDB Enterprise Server configuration file to change. For Centos, RedHat, and similar distributions this will be in /etc/my.cnf.d/.

In the [mariadb] section add the lines:

interactive_timeout = value
wait_timeout = value
idle_transaction_timeout = value
idle_write_transaction_timeout = value
idle_readonly_transaction_timeout = value

Where value is in seconds and corresponds to the company defined value. Restart MariaDB Enterprise Server for these changes to take effect."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57169r841674_chk'
  tag severity: 'medium'
  tag gid: 'V-253717'
  tag rid: 'SV-253717r841676_rule'
  tag stig_id: 'MADB-10-006200'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-57120r841675_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
