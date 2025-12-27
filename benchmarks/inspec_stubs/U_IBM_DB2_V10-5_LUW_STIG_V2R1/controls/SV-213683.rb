control 'SV-213683' do
  title 'The audit information produced by DB2 must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Run the db2audit command to find the value of the datapath where the audit logs are stored.

     $db2audit describe

Only the instance owner needs write access to directory and users authorized to archive the audit logs need to have read access to the audit directory.

If any user other than the instance owner has write access to the audit directory, this is a finding.

If any user other than the users authorized to read audit log files have read access to audit directory, this is a finding.'
  desc 'fix', 'At the operating system level, remove the write permission from non-instance owner users on the audit directory.

At the operating system level, remove the  read permission from non-authorized users on the audit directory.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14904r295098_chk'
  tag severity: 'medium'
  tag gid: 'V-213683'
  tag rid: 'SV-213683r879577_rule'
  tag stig_id: 'DB2X-00-002300'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-14902r295099_fix'
  tag 'documentable'
  tag legacy: ['SV-89129', 'V-74455']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
