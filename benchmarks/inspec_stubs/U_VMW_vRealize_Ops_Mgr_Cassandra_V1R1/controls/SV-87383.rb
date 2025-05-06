control 'SV-87383' do
  title 'The Cassandra database logs must have the correct group-owner.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Review the Cassandra Server settings to ensure logs have the correct group-owner.

At the command prompt, execute the following command:

# ls -lL /storage/log/vcops/log/cassandra

If any file is not group-owned by "admin", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server logs to have the correct group-owner.

At the command prompt, execute the following command:

# chown admin /storage/log/vcops/log/cassandra/<file>

Replace <file> with any file that has the incorrect group-owner.'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72751'
  tag rid: 'SV-87383r1_rule'
  tag stig_id: 'VROM-CS-000075'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-79155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
