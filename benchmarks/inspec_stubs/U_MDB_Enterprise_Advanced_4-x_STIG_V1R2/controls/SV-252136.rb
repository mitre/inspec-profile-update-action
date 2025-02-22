control 'SV-252136' do
  title 'MongoDB must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

If an attacker were to gain access to audit tools, they could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.

'
  desc 'check', 'To ensure audit configurations are protected from unauthorized modification, the default installation of MongoDB restricts permission on the configuration file. 

Verify User ownership, Group ownership, and permissions on the MongoDB configuration file:

(default name and location is /etc/mongod.conf)

(The name and location for the MongoDB configuration file will vary according to local circumstances.) 

Using the default name and location the command would be:

stat /etc/mongod.conf

If the User owner is not mongod, this is a finding.

If the Group owner is not mongod, this is a finding.

If the filename is more permissive than 660, this is a finding.

Note that the audit destination cannot be modified at runtime.'
  desc 'fix', 'Run these commands: 

chown mongod %MongoDB configuration file% 
chgrp mongod %MongoDB configuration file% 
chmod 660 %MongoDB configuration file%

(The name and location for the %MongoDB configuration file% will vary according to local circumstances. The default name and location is /etc/mongod.conf.) 

Using the default name and location the commands would be:

chown mongod /etc/mongod.conf  
chgrp  mongod /etc/mongod.conf  
chmod 660 /etc/mongod.conf 

The output of the command:

stat /etc/mongod.conf

should look similar to the following for a correctly owned and permissioned %MongoDB configuration file% (default /etc/mongod.conf):

stat /etc/mongod.conf
  File:/etc/mongod.conf
  Size: 1034              Blocks: 8          IO Block: 4096   regular file
Device: 802h/2050d        Inode: 16340       Links: 1
Access: (0660/-rw-rw----)  Uid: (  997/  mongod)   Gid: (  996/  mongod)
Context: system_u:object_r:etc_t:s0
Access: 2020-03-16 14:15:17.777000000 -0400
Modify: 2020-03-16 12:50:45.567000000 -0400
Change: 2020-03-16 14:27:32.451000000 -0400
 Birth: -'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55592r813788_chk'
  tag severity: 'medium'
  tag gid: 'V-252136'
  tag rid: 'SV-252136r813790_rule'
  tag stig_id: 'MD4X-00-000300'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-55542r813789_fix'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
