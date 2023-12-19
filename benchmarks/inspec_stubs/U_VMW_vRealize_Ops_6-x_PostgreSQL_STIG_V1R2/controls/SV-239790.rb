control 'SV-239790' do
  title 'The vROps PostgreSQL DB must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/*conf* /var/vmware/vpostgres/9.3/.pgpass

If the group-owner of any configuration file is not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users <file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43023r663745_chk'
  tag severity: 'medium'
  tag gid: 'V-239790'
  tag rid: 'SV-239790r879581_rule'
  tag stig_id: 'VROM-PG-000130'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-42982r663746_fix'
  tag 'documentable'
  tag legacy: ['SV-98903', 'V-88253']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
