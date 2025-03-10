control 'SV-251203' do
  title 'The audit information produced by Redis Enterprise DBMS must be protected from unauthorized modification.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be impossible to achieve. 

To ensure the veracity of audit data the information system and/or the application must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods that will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions and limiting log data locations. 

Applications providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding user rights in order to make access decisions regarding the modification of audit data.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity. 

Modification of database audit data could mask the theft of, or the unauthorized modification of, sensitive data stored in the database.'
  desc 'check', 'To investigate the log files used by Redis Enterprise, perform the following steps:
1. SSH into the server running Redis Enterprise.
2. Issue the command cd /var/opt/redislabs/log
3. Issue the command ls -ltr ./

Investigate the permissions on these files. These permissions should be 640 or 660 and assigned to the installation user and group or another appropriate group. If the permissions are readable by other or assigned an inappropriate owner/group, this is a finding.

Redis Enterprise does not support the ability to perform transaction logging.'
  desc 'fix', 'To investigate the log files used by Redis Enterprise, perform the following steps:
1. SSH into the server running Redis Enterprise.
2. Issue the command chmod 640 /var/opt/redislabs/log/* to change permissions of log files that are not appropriately assigned permissions.
3. Issue the command chown owner:group -R /var/opt/redislabs/log/ if the ownership is not correct where the owner and group are substituted for the appropriate owner and group.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54638r804797_chk'
  tag severity: 'medium'
  tag gid: 'V-251203'
  tag rid: 'SV-251203r804799_rule'
  tag stig_id: 'RD6X-00-006500'
  tag gtitle: 'SRG-APP-000119-DB-000060'
  tag fix_id: 'F-54592r804798_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
