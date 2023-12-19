control 'SV-96601' do
  title 'MongoDB must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.

'
  desc 'check', 'Verify the permissions for the following database files or directories:

MongoDB default configuration file: "/etc/mongod.conf"
MongoDB default data directory: "/var/lib/mongo"

If the owner and group are not both "mongod", this is a finding.

If the file permissions are more permissive than "755", this is a finding.'
  desc 'fix', 'Correct the permission to the files and/or directories that are in violation.

MongoDB Configuration file (default location): 
chown mongod:mongod /etc/mongod.conf
chmod 755 /etc/mongod.conf

MongoDB data file directory (default location): 
chown -R mongod:mongod/var/lib/mongo
chmod -R 755/var/lib/mongo'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81887'
  tag rid: 'SV-96601r1_rule'
  tag stig_id: 'MD3X-00-000470'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-88737r1_fix'
  tag satisfies: ['SRG-APP-000243-DB-000373', 'SRG-APP-000243-DB-000374']
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
