control 'SV-239786' do
  title 'The audit information produced by the vROps PostgreSQL DB must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/pg_log/*.log

If the owner of any log files is not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users /storage/db/vcops/vpostgres/data/pg_log/<file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43019r663733_chk'
  tag severity: 'medium'
  tag gid: 'V-239786'
  tag rid: 'SV-239786r879577_rule'
  tag stig_id: 'VROM-PG-000110'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-42978r663734_fix'
  tag 'documentable'
  tag legacy: ['SV-98895', 'V-88245']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
