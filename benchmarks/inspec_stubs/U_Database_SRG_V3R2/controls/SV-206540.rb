control 'SV-206540' do
  title 'The audit information produced by the DBMS must be protected from unauthorized deletion.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods which will depend upon system architecture and design.

Some commonly employed methods include: ensuring log files enjoy the proper file system permissions utilizing file system protections; restricting access; and backing up log data to ensure log data is retained.

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Deletion of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'Review locations of audit logs, both internal to the database, and database audit logs located at the operating system level.

Verify there are appropriate controls and permissions to protect the audit information from unauthorized deletion.

If appropriate controls and permissions do not exist, this is a finding.'
  desc 'fix', 'Apply controls and modify permissions to protect database audit log data from unauthorized deletion, whether stored in the database itself or at the OS level.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6800r291288_chk'
  tag severity: 'medium'
  tag gid: 'V-206540'
  tag rid: 'SV-206540r617447_rule'
  tag stig_id: 'SRG-APP-000120-DB-000061'
  tag gtitle: 'SRG-APP-000120'
  tag fix_id: 'F-6800r291289_fix'
  tag 'documentable'
  tag legacy: ['SV-42732', 'V-32395']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
