control 'SV-235096' do
  title 'MySQL Database Server 8.0  must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a Database Management System (DBMS). Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof.  In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement, are synonyms.)'
  desc 'check', "Determine whether the system documentation specifies limits on the number of concurrent MySQL database server 8.0 sessions.

Review the concurrent-sessions settings in the MySQL database server and/or the applications using it, and/or the system software supporting it. 

MySQL global variable max_user_connections  limits the number of simultaneous connections that can be made by any given account.

To check global (default) concurrent-sessions settings in the MySQL database server, run the following query:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'max_user_connections' ;

If the value of MAX_USER_CONNECTIONS is 0 (unlimited) or greater than the site-specific maximum number of sessions, this is a finding.
 
Retrieve the settings for concurrent sessions for each user with the query: 
SELECT user, host, max_user_connections 
FROM mysql.user 
WHERE user not like 'mysql.%' and user not like 'root';

If the user account has a nonzero MAX_USER_CONNECTIONS resource limit, the session MAX_USER_CONNECTIONS value is set to that limit. Otherwise, the session max_user_connections value is set to the global value.

If the DBMS settings for concurrent sessions for each user is greater than the site-specific maximum number of sessions and nonzero, this is a finding."
  desc 'fix', "The MySQL Database Server 8.0 is capable of enforcing this restriction. If not configured to do so, configure it to do so.

Connect to the MySQL Database as an administrator.
To set the global default to 50: 
SET PERSIST max_user_connections=50;

Additionally, max user connections can be set per user as well as for a given period of time.
GRANT ALL ON customer.* TO 'francis'@'localhost'
WITH MAX_CONNECTIONS_PER_HOUR 5;
MAX_USER_CONNECTIONS 2;"
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38315r623408_chk'
  tag severity: 'medium'
  tag gid: 'V-235096'
  tag rid: 'SV-235096r638812_rule'
  tag stig_id: 'MYS8-00-000200'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-38278r623409_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
