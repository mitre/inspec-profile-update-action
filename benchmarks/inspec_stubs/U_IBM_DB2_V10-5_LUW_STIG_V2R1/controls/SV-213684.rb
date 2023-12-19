control 'SV-213684' do
  title 'The audit information produced by DB2 must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Run the db2audit command to find the value of the datapath where the audit logs are stored. 

     $db2audit describe

Only the instance owner needs write access to directory and users authorized to archive the audit logs need to have read access to the audit directory.

If any user other than the instance owner has write access to audit directory, this is a finding.

If any user other than the users authorized to read audit log files have read access to the audit directory, this is a finding.'
  desc 'fix', 'At the operating system level, remove the write permission from non-instance owner users on the audit directory.

At the operating system level, remove the  read permission from non-authorized users on the audit directory.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14905r295101_chk'
  tag severity: 'medium'
  tag gid: 'V-213684'
  tag rid: 'SV-213684r879578_rule'
  tag stig_id: 'DB2X-00-002400'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-14903r295102_fix'
  tag 'documentable'
  tag legacy: ['SV-89131', 'V-74457']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
