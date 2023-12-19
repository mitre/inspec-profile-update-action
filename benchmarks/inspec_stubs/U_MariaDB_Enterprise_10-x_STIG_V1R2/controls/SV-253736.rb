control 'SV-253736' do
  title 'MariaDB must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

Each connection to the MariaDB database requires the authentication of the user. The authentication remains in place for the connection until the connection is closed or the connection times out due to inactivity.'
  desc 'check', "The system parameter idle_transaction_timeout specifies in seconds when a connection will be terminated due to inactivity. After a connection is terminated, a new request to the database must be preceded by an authentication, which is not cached within the database.

Run the following SQL:
MariaDB> SHOW GLOBAL VARIABLES LIKE 'idle_transaction_timeout';

If the value is 0, this is a finding."
  desc 'fix', 'Verify that the idle_transaction_wait is set to a value greater than 0 or is set to the value needed by the administrator. The value of idle_transaction_wait can be validated by issuing SHOW VARIABLES. Example:

Locate the MariaDB Enterprise Server configuration files in /etc/my.cnf.d/. Add the following: 

Under the [mariadb] section: 

idle_transaction_timeout = 60

After making changes to the .cnf file, stop and restart the database service.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57188r841731_chk'
  tag severity: 'medium'
  tag gid: 'V-253736'
  tag rid: 'SV-253736r841733_rule'
  tag stig_id: 'MADB-10-008300'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-57139r841732_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
