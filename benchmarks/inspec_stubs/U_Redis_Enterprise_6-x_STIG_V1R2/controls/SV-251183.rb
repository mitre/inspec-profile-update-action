control 'SV-251183' do
  title 'Redis Enterprise DBMS must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful denial-of-service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, 2 might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', 'Redis sets this limit by default at 10k clients per shard. It reserves 32 for descriptors for internal use. The organization can set a limit based on its needs during the configuration. When the set limit is reached, Redis will deny all new incoming connections and inform senders "max number of clients reached".

To check for maximum connections, run the following command:
rladmin info db db:<insert_db_id> 

where db:1 would be:
rladmin info db db:1 

Search in the output for max_connections. If the max connections are greater than the organizationally defined value, this is a finding.

Note: Redis Enterprise 6 does support multiple users; however, it does not support the ability to limit connections per user. If using Redis Cluster, the max number of connections remains 10k; however, each node will use two connections (incoming/outgoing).'
  desc 'fix', 'To modify the number of maximum sessions, run the following command:

rladmin tune db <db_name> max_connections <number_of_connections>
e.g., - rladmin tune db inline-jp-staging max_connections 15000'
  impact 0.3
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54618r804737_chk'
  tag severity: 'low'
  tag gid: 'V-251183'
  tag rid: 'SV-251183r804739_rule'
  tag stig_id: 'RD6X-00-000100'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-54572r804738_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
