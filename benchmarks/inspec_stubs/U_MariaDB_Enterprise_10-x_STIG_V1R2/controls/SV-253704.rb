control 'SV-253704' do
  title 'The MariaDB must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).'
  desc 'Nonorganizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Nonorganizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the nation.'
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
  tag check_id: 'C-57156r841635_chk'
  tag severity: 'medium'
  tag gid: 'V-253704'
  tag rid: 'SV-253704r841637_rule'
  tag stig_id: 'MADB-10-004500'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-57107r841636_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
