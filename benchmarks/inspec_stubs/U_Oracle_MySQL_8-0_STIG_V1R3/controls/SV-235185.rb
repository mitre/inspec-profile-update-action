control 'SV-235185' do
  title 'The MySQL Database Server 8.0 must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance.

Each connection to mysqld runs in a separate thread. Kill a connection by killing the connections thread with the KILL processlist_id statement.

Thread processlist identifiers can be determined from the ID column of the INFORMATION_SCHEMA PROCESSLIST table, the Id column of SHOW PROCESSLIST output, and the PROCESSLIST_ID column of the Performance Schema threads table."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

Determine the situations where a user must reauthenticate. Check if the mechanisms that handle such situations use the following SQL:

To make a single user reauthenticate, an existing connection must be present:

To search for a specific user:
SELECT * FROM information_schema.PROCESSLIST where user ='<name> and host like '%';

To review all connections:
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;

Note the ID(s) (processlist_id) of the connection(s) for the user that must reauthenticate.

To make a user reauthenticate, run the following for each ID returned above (as they can have multiple connections).

KILL CONNECTION processslist_id;

If the provided SQL does not force reauthentication, this is a finding."
  desc 'fix', 'Modify and/or configure MySQL and related applications and tools so that users are always required to reauthenticate when changing role or escalating privileges.

To make a single user reauthenticate, the following must be present:

KILL CONNECTION processslist_id;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38404r623675_chk'
  tag severity: 'medium'
  tag gid: 'V-235185'
  tag rid: 'SV-235185r855583_rule'
  tag stig_id: 'MYS8-00-011100'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-38367r623676_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
