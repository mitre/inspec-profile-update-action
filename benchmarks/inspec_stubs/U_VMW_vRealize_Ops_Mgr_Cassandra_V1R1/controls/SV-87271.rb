control 'SV-87271' do
  title 'The Cassandra database logs must have the correct owner.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Review the Cassandra Server to ensure logs have the correct owner.

At the command prompt, execute the following command:

# ls -lL /storage/log/vcops/log/cassandra

If any file is not owned by "admin", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server logs to have the correct owner.

At the command prompt, execute the following command:

# chown admin /storage/log/vcops/log/cassandra/<file>

Replace <file> with any file that has the incorrect owner.'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72639'
  tag rid: 'SV-87271r1_rule'
  tag stig_id: 'VROM-CS-000070'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-79041r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
