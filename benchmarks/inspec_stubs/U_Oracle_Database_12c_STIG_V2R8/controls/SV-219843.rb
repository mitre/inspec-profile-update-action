control 'SV-219843' do
  title 'Unauthorized database links must not be defined and active.'
  desc 'DBMS links provide a communication and data transfer path definition between two databases that may be used by malicious users to discover and obtain unauthorized access to remote systems. Database links between production and development DBMSs provide a means for developers to access production data not authorized for their access or to introduce untested or unauthorized applications to the production database. Only protected, controlled, and authorized downloads of any production data to use for development may be allowed. Only applications that have completed the configuration management process may be introduced by the application object owner account to the production system.'
  desc 'check', "From SQL*Plus:
  select db_link||': '||host from dba_db_links;

If no links are returned, this check is not a finding.

Review documentation for definitions of authorized database links to external interfaces.

The documentation should include:

- Any remote access to the database
- The purpose or function of the remote connection
- Any access to data or procedures stored externally to the local DBMS
- Any network ports or protocols used by remote connections, whether the remote connection is to a production, test, or development system
- Any security accounts used by DBMS to access remote resources or objects

If any unauthorized database links are defined or the definitions do not match the documentation, this is a finding.

Note: findings for production-development links under this check are assigned to the production database only.

If any database links are defined between the production database and any test or development databases, this is a finding.

If remote interface documentation does not exist or is incomplete, this is a finding."
  desc 'fix', 'Document all remote or external interfaces used by the DBMS to connect to or allow connections from remote or external sources.

Include with the documentation as appropriate, any network ports or protocols, security accounts, and the sensitivity of any data exchanged.

Do not define or configure database links between production databases and test or development databases.

Note: Oracle Database Advanced Replication is deprecated in Oracle Database 12c. Use Oracle GoldenGate to replace all features of Advanced Replication, including multimaster replication, updatable materialized views, hierarchical materialized views, and deployment templates.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21554r533068_chk'
  tag severity: 'medium'
  tag gid: 'V-219843'
  tag rid: 'SV-219843r879887_rule'
  tag stig_id: 'O121-BP-023200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21553r533069_fix'
  tag 'documentable'
  tag legacy: ['SV-75941', 'V-61451']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
