control 'SV-100013' do
  title 'The vRA PostgreSQL configuration files must have the correct group-ownership.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/*conf*

If the group-owner of any configuration file is not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users <file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89363'
  tag rid: 'SV-100013r1_rule'
  tag stig_id: 'VRAU-PG-000120'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-96105r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
