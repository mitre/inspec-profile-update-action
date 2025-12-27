control 'SV-219715' do
  title 'Unauthorized database links must not be defined and active.'
  desc 'DBMS links provide a communication and data transfer path definition between two databases that may be used by malicious users to discover and obtain unauthorized access to remote systems. Database links between production and development DBMSs provide a means for developers to access production data not authorized for their access or to introduce untested or unauthorized applications to the production database. Only protected, controlled, and authorized downloads of any production data to use for development should be allowed. Only applications that have completed the configuration management process should be introduced by the application object owner account to the production system.'
  desc 'check', "From SQL*Plus:
select db_link||': '||host from dba_db_links;

If no links are returned, this check is Not a Finding.

Review documentation for definitions of authorized database links to external interfaces.

The documentation should include:

- Any remote access to the database
- The purpose or function of the remote connection
- Any access to data or procedures stored externally to the local DBMS
- Any network ports or protocols used by remote connections, whether the remote connection is to a production, test, or development system
- Any security accounts used by DBMS to access remote resources or objects

If any unauthorized database links are defined or the definitions do not match the documentation, this is a Finding.

NOTE: Findings for production-development links under this check are assigned to the production database only.

If any database links are defined between the production database and any test or development databases, this is a Finding.

If remote interface documentation does not exist or is incomplete, this is a Finding."
  desc 'fix', 'Document all remote or external interfaces used by the DBMS to connect to or allow connections from remote or external sources.

Include with the documentation as appropriate, any network ports or protocols, security accounts, and the sensitivity of any data exchanged.

Do not define or configure database links between production databases and test or development databases.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21440r306994_chk'
  tag severity: 'medium'
  tag gid: 'V-219715'
  tag rid: 'SV-219715r401224_rule'
  tag stig_id: 'O112-BP-023200'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21439r306995_fix'
  tag 'documentable'
  tag legacy: ['SV-68241', 'V-54001']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
