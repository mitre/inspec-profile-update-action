control 'SV-240292' do
  title 'The vRA PostgreSQL configuration files must have the correct ownership.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/*conf*

If the owner of any configuration file is not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users <file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43525r668718_chk'
  tag severity: 'medium'
  tag gid: 'V-240292'
  tag rid: 'SV-240292r879580_rule'
  tag stig_id: 'VRAU-PG-000115'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-43484r668719_fix'
  tag 'documentable'
  tag legacy: ['SV-100011', 'V-89361']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
