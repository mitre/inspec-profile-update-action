control 'SV-235856' do
  title 'Docker Enterprise /etc/docker directory permissions must be set to 755 or more restrictive.'
  desc 'Verify that the /etc/docker directory permissions are correctly set to 755 or more restrictive.

/etc/docker directory contains certificates and keys in addition to various sensitive files. Hence, it should only be writable by root to maintain the integrity of the directory.

By default, the permissions for this directory are correctly set to 755.'
  desc 'check', 'Execute the below command to verify that the directory has permissions of 755 or more restrictive:

stat -c %a /etc/docker

If the permissions are not set to 755, this is a finding.'
  desc 'fix', 'set the permissions for the directory to 755.

Execute the following command:
chmod 755 /etc/docker'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39075r627693_chk'
  tag severity: 'medium'
  tag gid: 'V-235856'
  tag rid: 'SV-235856r627695_rule'
  tag stig_id: 'DKER-EE-005220'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39038r627694_fix'
  tag 'documentable'
  tag legacy: ['SV-104887', 'V-95749']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
