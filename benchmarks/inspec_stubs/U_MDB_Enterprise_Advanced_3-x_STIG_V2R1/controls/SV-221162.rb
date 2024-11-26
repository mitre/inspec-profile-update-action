control 'SV-221162' do
  title 'MongoDB must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data.

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records.

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.

'
  desc 'check', %q(Verify User ownership, Group ownership, and permissions on the “<MongoDB configuration file>":

(default name and location is '/etc/mongod.conf')

(The name and location for the MongoDB configuration file will vary according to local circumstances.) 

Using the default name and location the command would be:

> ls –ald /etc/mongod.conf

If the User owner is not "mongod", this is a finding.

If the Group owner is not "mongod", this is a finding.

If the filename is more permissive than "700", this is a finding.)
  desc 'fix', %q(Run these commands: 

"chown mongod <MongoDB configuration file>" 
"chgrp mongod <MongoDB configuration file>" 
"chmod 700 <<MongoDB configuration file>"

(The name and location for the MongoDB configuration file will vary according to local circumstances. The default name and location is '/etc/mongod.conf'.) 

Using the default name and location the commands would be:

> chown mongod /etc/mongod.conf 
> chgrp mongod /etc/mongod.conf 
> chmod 700 /etc/mongod.conf)
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22877r410980_chk'
  tag severity: 'medium'
  tag gid: 'V-221162'
  tag rid: 'SV-221162r410982_rule'
  tag stig_id: 'MD3X-00-000220'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-22866r410981_fix'
  tag satisfies: ['SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000122-DB-000204']
  tag 'documentable'
  tag legacy: ['SV-96565', 'V-81851']
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
