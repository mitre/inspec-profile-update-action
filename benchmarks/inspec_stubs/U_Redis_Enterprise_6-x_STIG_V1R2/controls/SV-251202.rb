control 'SV-251202' do
  title 'The audit information produced by Redis Enterprise DBMS must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions, utilizing file system protections, and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
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
  tag check_id: 'C-54637r804794_chk'
  tag severity: 'medium'
  tag gid: 'V-251202'
  tag rid: 'SV-251202r804796_rule'
  tag stig_id: 'RD6X-00-006400'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-54591r804795_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
