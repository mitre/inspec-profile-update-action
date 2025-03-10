control 'SV-253666' do
  title 'MariaDB must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing MariaDB. Unlimited concurrent connections to MariaDB could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to MariaDB (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to MariaDB by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', 'To check the number of connections allowed for each user, as the database administrator, run the following SQL:

MariaDB> SELECT user, max_user_connections FROM mysql.user;

If any users have more connections configured than documented, this is a finding. A value of 0 indicates unlimited and is a finding.'
  desc 'fix', "To limit the number of connections allowed by a specific user, as a user with appropriate privileges, run the following SQL:

MariaDB> GRANT USAGE ON *.* TO  'username'@'host'  WITH MAX_USER_CONNECTIONS number_of_connections;"
  impact 0.3
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57118r841521_chk'
  tag severity: 'low'
  tag gid: 'V-253666'
  tag rid: 'SV-253666r841523_rule'
  tag stig_id: 'MADB-10-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-57069r841522_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
