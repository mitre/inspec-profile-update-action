control 'SV-96563' do
  title 'The audit information produced by MongoDB must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', %q(Verify User ownership, Group ownership, and permissions on the "<MongoDB auditLog directory>":

> ls –ald <MongoDB auditLog data directory>

If the User owner is not "mongod", this is a finding.

If the Group owner is not "mongod", this is a finding.

If the directory is more permissive than "700", this is a finding.

(The path for the MongoDB auditLog directory will vary according to local circumstances. The auditLog directory will be found in the MongoDB configuration file whose default location is '/etc/mongod.conf'.) 

To find the auditLog directory name, view and search for the entry in the MongoDB configuration file for the auditLog.path:

Example:

auditLog:
destination: file
format: BSON
path: /var/lib/mongo/auditLog.bson

Given the example above, to find the auditLog directory name run the following command:

> dirname /var/lib/mongo/auditLog.bson
the output will be the "<MongoDB auditLog directory>"

/var/lib/mongo)
  desc 'fix', %q(Run these commands: 

"chown mongod <MongoDB auditLog directory>" 
"chgrp mongod <MongoDB auditLog directory>" 
"chmod 700 <<MongoDB auditLog directory>"

(The path for the MongoDB auditLog directory will vary according to local circumstances. The auditLog directory will be found in the MongoDB configuration file whose default location is '/etc/mongod.conf'.) 

To find the auditLog directory name, view and search for the entry in the MongoDB configuration file for the auditLog.path:

Example:

auditLog:
destination: file
format: BSON
path: /var/lib/mongo/auditLog.bson

Given the example above, to find the auditLog directory name run the following command:

> dirname /var/lib/mongo/auditLog.bson
the output will be the "<MongoDB auditLog directory>"

/var/lib/mongo)
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81641r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81849'
  tag rid: 'SV-96563r1_rule'
  tag stig_id: 'MD3X-00-000190'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-88699r1_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
