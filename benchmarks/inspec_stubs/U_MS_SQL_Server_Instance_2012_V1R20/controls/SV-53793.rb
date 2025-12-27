control 'SV-53793' do
  title 'The number of concurrent SQL Server sessions for each system account must be limited.'
  desc 'A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks. For example, boundary protection devices can filter certain types of packets to protect devices on an organization’s internal network from being directly affected by DoS attacks.

One way SQL Server can limit exposure to DoS attacks is to restrict the number of connections that can be opened by a single user. SQL Server supports this through the use of logon triggers.  (Note, however, that this need not be the only, or even the principal, means for satisfying this requirement.  Depending on the architecture and capabilities of the network and application, a network device or an application may be more suitable for providing this protection.)

When determining the appropriate values for this limit, take the characteristics of the various kinds of user into account, and bear in mind that some applications and some users may need to have multiple sessions open.  For example, while a standard account using a simple application may never need more than, say, five connections, a database administrator using SQL Server Management Studio may need significantly more, because each tab in that application counts as a distinct session.

Architectural note:  In SQL Server, a count of active sessions by user can be obtained from one of the dynamic management views.   For example:

	SELECT original_login_name, count(*) 
	FROM sys.dm_exec_sessions
	WHERE is_user_process = 1
	GROUP BY original_login_name;

However, for this to return an accurate count in a logon trigger, the user would have to have the View Server State privilege.  (Without this privilege, the trigger sees information only about the current session, so would always return a count of one.)  View Server State would give that user access to a wide swath of information about the server, violating SQL2-00-004100.  One way to avoid this exposure is to create a summary table, and a view of that table that restricts each user to seeing his/her own count, and establish a frequently-run background job to refresh the table (using the above query or similar).  The logon trigger then queries the view to obtain a count that is accurate enough for most purposes.'
  desc 'check', "Review the system documentation to determine whether any limits have been defined.  If not, this is a finding.

If one limit has been defined but is not applied to all users, including privileged administrative accounts, this is a finding.

If multiple limits have been defined, to accommodate different types of user, verify that together they cover all users.  If not, this is a finding. 

If a mechanism other than a logon trigger is used, verify its correct operation by the appropriate means.  If it does not work correctly, this is a finding.

Otherwise, determine if a logon trigger exists:

EITHER, in SQL Server Management Studio's Object Explorer tree: 
Expand [SQL Server Instance] >> Security >> Server Objects >> Triggers

OR run the query:
SELECT * FROM master.sys.server_triggers;

If no triggers are listed, this is a finding.

If triggers are listed, identify the one(s) limiting the number of concurrent sessions per user.  If none are found, this is a finding. If they are present but disabled, this is a finding.  

Examine the trigger source code for logical correctness and for compliance with the documented limit(s).  If errors or variances exist, this is a finding.

Verify that the system does execute the trigger(s) each time a user session is established.  If it does not operate correctly for all types of user, this is a finding."
  desc 'fix', 'Establish the limit(s) appropriate to the type(s) of user account accessing the SQL Server instance, and record them in the system documentation.

Implement one or more logon triggers to enforce the limit(s), without exposing the dynamic management views to general users.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47880r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41311'
  tag rid: 'SV-53793r4_rule'
  tag stig_id: 'SQL2-00-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-46702r5_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
