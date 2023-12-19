control 'SV-240290' do
  title 'The vRA PostgreSQL database must have the correct group-ownership on the log files.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/pg_log/*.log

If the group-owner of any log files are not "postgres:users", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chown postgres:users /storage/db/pgdata/pg_log/<file_name>

Replace <file_name> with files to be modified.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43523r668712_chk'
  tag severity: 'medium'
  tag gid: 'V-240290'
  tag rid: 'SV-240290r879578_rule'
  tag stig_id: 'VRAU-PG-000105'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-43482r668713_fix'
  tag 'documentable'
  tag legacy: ['SV-100007', 'V-89357']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
