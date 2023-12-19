control 'SV-253698' do
  title 'If passwords are used for authentication, MariaDB must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', 'MariaDB by default only sends passwords encrypted. However, when authenticating via the PAM Authentication Plugin, the password is sent in cleartext. Thus when using PAM authentication, it is recommended to use TLS/SSL encryption for all database connections. 

If using PAM authentication, verify TLS/SSL is in use. 

Run the following database command: 

MariaDB> STATUS; 

Verify the line which starts with "SSL:" is as expected. If it returns "Not in use", this is a finding.'
  desc 'fix', 'As the administrator locate the MariaDB configuration file to change. This varies depending on setup and how configuration files are managed but should be in /etc/my.cnf.d/. It is recommended to have a separate configuration file within this directory for SSL connection information.

In the [server] section add the lines for SSL:

ssl
ssl-ca=/path/to/ssl/ca-cert.pem
ssl-cert=/path/to/ssl/server-cert.pem
ssl-key=/path/to/ssl/server-key.pem

Restart of the MariaDB Server and verify SSL is being used.

MariaDB> STATUS; 

Verify line beginning with "SSL:".'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57150r841617_chk'
  tag severity: 'high'
  tag gid: 'V-253698'
  tag rid: 'SV-253698r841619_rule'
  tag stig_id: 'MADB-10-003900'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-57101r841618_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
