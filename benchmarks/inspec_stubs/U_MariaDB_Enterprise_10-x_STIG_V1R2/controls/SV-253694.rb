control 'SV-253694' do
  title 'MariaDB must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.

It is recommended to not allow shared accounts, including root. The root user is known by all attackers, and often used in attempted attacks on the database servers.'
  desc 'check', 'All users should have individual accounts with appropriate privileges. The root users should be removed after administrative accounts with SUPER privilege are created. Query all users and determine if any are suspected shared accounts. Document any necessary shared accounts.

MariaDB> SELECT user, host FROM mysql.user;

Determine if any accounts are shared. A shared account is defined as a username, hostname, and password that are used by multiple individuals to log in to MariaDB. An example of a shared account is the MariaDB root account – root@localhost.

If accounts are determined to be shared, determine if individuals are first individually authenticated. 

If individuals are not individually authenticated before using the shared account (e.g., by the operating system or possibly by an application making calls to the database), this is a finding. 

The key is individual accountability. If this can be traced, this is not a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.

Review contents of audit logs, traces, and data tables to confirm the identity of the individual user performing the action is captured.

If shared identifiers are found, and not accompanied by individual identifiers, this is a finding.'
  desc 'fix', "Remove shared accounts which are not documented and have been determined to not be necessary.

MariaDB> DROP USER 'user'@'hostname';"
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57146r841605_chk'
  tag severity: 'medium'
  tag gid: 'V-253694'
  tag rid: 'SV-253694r841607_rule'
  tag stig_id: 'MADB-10-003600'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-57097r841606_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
