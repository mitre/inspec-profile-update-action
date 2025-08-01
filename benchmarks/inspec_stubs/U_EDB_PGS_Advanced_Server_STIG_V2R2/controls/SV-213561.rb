control 'SV-213561' do
  title 'The EDB Postgres Advanced Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', 'Determine whether the system documentation specifies limits on the number of concurrent DBMS sessions per account by type of user. If it does not, assume a limit of 10 for database administrators and 2 for all other users.

Execute the following SQL as enterprisedb:

SELECT rolname, rolconnlimit FROM pg_roles;

If rolconnlimit is -1 or larger than the system documentation limits for any rolname, this is a finding.'
  desc 'fix', 'Execute the following SQL as enterprisedb:

SELECT rolname, rolconnlimit FROM pg_roles;

For any roles where rolconnlimit is -1 or larger than the system documentation limits, execute this SQL as enterprisedb:.

ALTER USER <role> WITH CONNECTION LIMIT <desired connection limit>;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14783r289995_chk'
  tag severity: 'medium'
  tag gid: 'V-213561'
  tag rid: 'SV-213561r508024_rule'
  tag stig_id: 'PPS9-00-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-14781r289996_fix'
  tag 'documentable'
  tag legacy: ['SV-83479', 'V-68875']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
