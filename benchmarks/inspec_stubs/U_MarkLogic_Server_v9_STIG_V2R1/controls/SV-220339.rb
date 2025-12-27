control 'SV-220339' do
  title 'MarkLogic Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)

Limiting Concurrent Requests with User Session Limits
There is an option on each App Server (HTTP, ODBC, XDBC, and WebDAV Server) configuration to limit the number of concurrent requests a user can have against that App Server. A concurrent request is defined to be a request against that App Server from the same user while another request from the same user is still active. Each App Server has a concurrent request limit configuration parameter. The default is 0, which means there is no limit to the number of concurrent requests. The value must be an integer greater than or equal to 0.

Setting the concurrent request limit configuration parameter to a value other than 0 limits the number of concurrent requests any user can run against that App Server to the specified number. For example, by setting the number to 3, any requests made by a user named Raymond while 3 requests from Raymond are running will fail with an exception.

When the limit is reached, the application will throw a 403 (forbidden) error with the XDMP-REQUESTLIMIT exception.'
  desc 'check', 'Determine whether the system documentation specifies limits on the number of concurrent DBMS sessions per account by type of user. If it does not, assume a limit of 10 for database administrators and 2 for all other users.

Check the concurrent-sessions settings in the MarkLogic. 

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select the App Server in which in which to check session limits. The App Server Configuration page displays.
5. Inspect the concurrent request limit field; a value of 0 means there is no concurrent request limit (unlimited), and this is a finding. 
6. If a value other than 0 but not equal to the organization-defined number is set, this is a finding.
7. Repeat for all App Servers.'
  desc 'fix', 'Determine whether the system documentation specifies limits on the number of concurrent DBMS sessions per account by type of user. If it does not, assume a limit of 10 for database administrators and 2 for all other users.

Fix the concurrent-sessions settings in MarkLogic.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the App Server to be fixed resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Select the App Server in which in which to fix session limits. The App Server Configuration page displays.
5. In the concurrent request limit field, enter a value corresponding to the organization-defined maximum number of concurrent user sessions to allow.
6. Repeat for all App Servers.'
  impact 0.3
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22054r531246_chk'
  tag severity: 'low'
  tag gid: 'V-220339'
  tag rid: 'SV-220339r622777_rule'
  tag stig_id: 'ML09-00-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-22043r401469_fix'
  tag 'documentable'
  tag legacy: ['SV-110025', 'V-100921']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
