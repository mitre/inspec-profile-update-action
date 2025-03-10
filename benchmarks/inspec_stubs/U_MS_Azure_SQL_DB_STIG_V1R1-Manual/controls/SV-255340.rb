control 'SV-255340' do
  title 'Azure SQL Database must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the system owner, data owner, or organization requires additional assurance, this is a finding."
  desc 'fix', 'Determine the situations when a user-initiated database session must be terminated.

Note: The user running the commands shown below requires the KILL DATABASE CONNECTION permission. The server-level principal login has the KILL DATABASE CONNECTION.

In the SQL Server Management Studio ,as an authenticated user connected to master database, run the following command to list all user sessions:

SELECT c.session_id,host_name,program_name,nt_domain, login_name, connect_time, last_request_end_time 
FROM sys.dm_exec_sessions AS s
JOIN sys.dm_exec_connections AS c ON s.session_id= c.session_id;

https://docs.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-exec-sessions-transact-sql?view=azuresqldb-current

Example output:
76        MyComputer    Microsoft SQL Server Management Studio - Transact-SQL IntelliSense NULL            MyLogin           2022-08-26 20:08:38.170         2022-08-26 20:22:39.697

From the output identify the names of users whose session_ids should be terminated. Using the user for each session to be terminated, run the following command (still in SQL Server Management Studio).

Example to terminate user "MyLogin" sessions from example output:
KILL <SPID> - where <SPID> is the Session_ID of the session you want to terminate.

Reference:
https://docs.microsoft.com/en-us/sql/t-sql/language-elements/kill-transact-sql?view=azuresqldb-current'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59013r871144_chk'
  tag severity: 'medium'
  tag gid: 'V-255340'
  tag rid: 'SV-255340r871146_rule'
  tag stig_id: 'ASQL-00-010200'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-58957r871145_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
