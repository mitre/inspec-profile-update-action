control 'SV-214053' do
  title 'PostgreSQL must provide non-privileged users with error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any PostgreSQL or associated application providing too much information in error messages on the screen or printout risks compromising the data and security of the system. The structure and content of error messages need to be carefully considered by the organization and development team.

Databases can inadvertently provide a wealth of information to an attacker through improperly handled error messages. In addition to sensitive business or personal information, database errors can provide host names, IP addresses, user names, and other system information not required for troubleshooting but very useful to someone targeting the system.

Carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', "As the database administrator, run the following SQL:

SELECT current_setting('client_min_messages');

If client_min_messages is not set to error, this is a finding."
  desc 'fix', 'Note: The following instructions use the PGDATA and PGVER environment variables. See supplementary content APPENDIX-F for instructions on configuring PGDATA and APPENDIX-H for PGVER.

As the database administrator, edit "postgresql.conf": 

$ sudo su - postgres 
$ vi $PGDATA/postgresql.conf 

Change the client_min_messages parameter to be "error": 

client_min_messages = error 

Reload the server with the new configuration (this just reloads settings currently in memory; it will not cause an interruption): 

# SYSTEMD SERVER ONLY 
$ sudo systemctl reload postgresql-${PGVER?}

# INITD SERVER ONLY 
$ sudo service postgresql-${PGVER?} reload'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15269r360790_chk'
  tag severity: 'medium'
  tag gid: 'V-214053'
  tag rid: 'SV-214053r508027_rule'
  tag stig_id: 'PGS9-00-000600'
  tag gtitle: 'SRG-APP-000266-DB-000162'
  tag fix_id: 'F-15267r360791_fix'
  tag 'documentable'
  tag legacy: ['SV-87503', 'V-72851']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
