control 'SV-252142' do
  title 'MongoDB must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The purpose of this control is to prevent information, including encrypted representations of information, produced by the actions of a prior user/role (or the actions of a process acting on behalf of a prior user/role) from being available to any current user/role (or current process) that obtains access to a shared system resource (e.g., registers, main memory, secondary storage) after the resource has been released back to the information system. Control of information in shared resources is also referred to as object reuse.

'
  desc 'check', 'By default, the MongoDB official installation packages restrict user and group ownership and read/write permissions on the underlying data files and critical configuration files from other operating system users. 

In addition, process and memory isolation is used by default. System administrators should also consider if whole database encryption would be an effective control on an application basis.

Run the following commands to verify proper permissions for the following database files or directories:

stat /etc/mongod.conf

If the owner and group are not both mongod, this is a finding.

If the file permissions are more permissive than 600, this is a finding.

stat  /var/lib/mongo

If the owner and group are not both mongod, this is a finding.

If the file permissions are more permissive than 755, this is a finding.

ls -l /var/lib/mongo

If the owner and group of  any file or sub-directory is not mongod, this is a finding.

If the permission of any file in the main directory (/var/lib/mongo) or sub-directory of (/var/lib/mongo) is more permissive than 600, this is a finding.

If the permission of any sub-directory of (/var/lib/mongo) is more permissive than 700, this is a finding.'
  desc 'fix', 'Correct the permission to the files and/or directories that are in violation.

%MongoDB configuration file% (default location /etc/mongod.conf): 

chown mongod:mongod /etc/mongod.conf
chmod 600 /etc/mongod.conf

MongoDB datafiles and directories (default location /var/lib/mongo): 

chown -R mongod:mongod /var/lib/mongo
chmod 755 /var/lib/mongo

find /var/lib/mongo/* -type f | xargs  chmod 600
find /var/lib/mongo/* -type d | xargs  chmod 700'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55598r817008_chk'
  tag severity: 'medium'
  tag gid: 'V-252142'
  tag rid: 'SV-252142r817009_rule'
  tag stig_id: 'MD4X-00-000900'
  tag gtitle: 'SRG-APP-000243-DB-000373'
  tag fix_id: 'F-55548r813807_fix'
  tag satisfies: ['SRG-APP-000243-DB-000373', 'SRG-APP-000243-DB-000374']
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
