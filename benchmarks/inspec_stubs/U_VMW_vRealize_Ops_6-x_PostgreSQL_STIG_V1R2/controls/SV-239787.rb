control 'SV-239787' do
  title 'The audit information produced by the vROps PostgreSQL DB must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/pg_log/*.log

If the group-owner of any log files is not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users /storage/db/vcops/vpostgres/data/pg_log/<file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43020r663736_chk'
  tag severity: 'medium'
  tag gid: 'V-239787'
  tag rid: 'SV-239787r879578_rule'
  tag stig_id: 'VROM-PG-000115'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-42979r663737_fix'
  tag 'documentable'
  tag legacy: ['SV-98897', 'V-88247']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
