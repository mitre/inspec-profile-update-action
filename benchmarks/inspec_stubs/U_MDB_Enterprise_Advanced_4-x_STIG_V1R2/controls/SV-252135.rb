control 'SV-252135' do
  title 'The audit information produced by MongoDB must be protected from unauthorized access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location.

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', "MongoDB must not permit access to its audit logs by unprivileged users. The official installation packages restrict which operating system users and groups may read or modify files. The audit log destination is not configured or created at installation time and must be manually done with appropriate ownership and permissions applied with the MongoDB user and MongoDB group.

Check the MongoDB configuration file (default location: /etc/mongod.conf) for a key named auditLog with  destination set to file. 

Example shown below:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson

-OR-

auditLog:
destination: syslog

If auditLog does not exist, this is a finding.

If the auditLog.destination is file in the MongoDB configuration file (default location /etc/mongod.conf), then the following will check ownership and permissions of the MongoDB auditLog directory:

Verify User ownership, Group ownership, and permissions on the MongoDB auditLog directory:

stat MongoDB auditLog directory

If the User owner is not mongod, this is a finding.

If the Group owner is not mongod, this is a finding.

If the directory is more permissive than 700, this is a finding.

To find the auditLog directory name,  view and search for the entry in the MongoDB configuration file (default location /etc/mongod.conf) for auditLog.destination.  If this parameters value is file then use the directory portion of the auditLog.path setting as the MongoDB auditLog directory location.

Example:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson

Given the example above, to find the auditLog directory ownership and permissions, run the following command:

stat /var/log/mongodb/audit

The output will look similar to the following output:

  File: '/var/log/mongodb/audit'
  Size: 48                Blocks: 0          IO Block: 4096   directory
Device: 808h/2056d        Inode: 245178      Links: 2
Access: (0700/drwx------)  Uid: (  997/  mongod)   Gid: (  996/  mongod)
Context: unconfined_u:object_r:mongod_log_t:s0
Access: 2020-03-16 12:51:16.816000000 -0400
Modify: 2020-03-16 12:50:48.722000000 -0400
Change: 2020-03-16 12:50:48.722000000 -0400
 Birth: -"
  desc 'fix', 'It is recommended to use the official installation packages provided by MongoDB. In the event the software was installed manually and permissions need to be restricted, consider a clean reinstallation. 

If the key name auditLog.destination is set to either syslog or console, then this requirement is not applicable as there is no physical directory that MongoDB can secure. Site security requirements and operating system security requirements will need to be reviewed to ensure appropriate settings for syslog and console destinations.

To correct finding where a physical auditLog directory exists (where auditLog.destination is set to file), run these commands: 

chown mongod %MongoDB auditLog directory%
chgrp mongod   %MongoDB auditLog directory%
chmod 700         %MongoDB auditLog directory%

(The path for the %MongoDB auditLog directory% will vary according to local circumstances.  The auditLog directory will be found in the %MongoDB configuration file% whose default location is /etc/mongod.conf.) 

To find the auditLog directory name, view and search for the entry in the %MongoDB configuration file% for the auditLog.path:

Example:

auditLog:
   destination: file
   format: BSON
   path: /var/log/mongodb/audit/auditLog.bson

Given the example above, the %MongoDB auditLog directory% is /var/log/mongodb/audit.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55591r813785_chk'
  tag severity: 'medium'
  tag gid: 'V-252135'
  tag rid: 'SV-252135r813787_rule'
  tag stig_id: 'MD4X-00-000200'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-55541r813786_fix'
  tag satisfies: ['SRG-APP-000118-DB-000059', 'SRG-APP-000119-DB-000060', 'SRG-APP-000120-DB-000061']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
