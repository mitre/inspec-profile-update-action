control 'SV-235855' do
  title 'Docker Enterprise /etc/docker directory ownership must be set to root:root.'
  desc 'Verify that the /etc/docker directory ownership and group-ownership is correctly set to root.

/etc/docker directory contains certificates and keys in addition to various sensitive files. Hence, it should be owned and group-owned by root to maintain the integrity of the directory.

By default, the ownership and group-ownership for this directory is correctly set to root.'
  desc 'check', "Ensure that /etc/docker directory ownership is set to root:root.

On CentOS host OS's, execute the below command to verify that the directory is owned and group-owned by root:
stat -c %U:%G /etc/docker 

If root:root is not displayed, this is a finding.

On Ubuntu host OS's, execute the below command to verify that the /etc/default/docker directory ownership is set to root:root:
stat -c %U:%G /etc/default/docker 

If root:root is not displayed, this is a finding."
  desc 'fix', "Set the ownership and group-ownership for the directory to root.

On CentOS host OS's, execute the following command:
chown root:root /etc/docker

On Ubuntu host OS's, execute the following command:
chown root:root /etc/default/docker"
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39074r627690_chk'
  tag severity: 'high'
  tag gid: 'V-235855'
  tag rid: 'SV-235855r627692_rule'
  tag stig_id: 'DKER-EE-005210'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39037r627691_fix'
  tag 'documentable'
  tag legacy: ['SV-104885', 'V-95747']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
