control 'SV-235867' do
  title 'Docker Enterprise daemon.json file ownership must be set to root:root.'
  desc 'Verify that the daemon.json file ownership and group-ownership is correctly set to root.

daemon.json file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be owned and group-owned by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable.'
  desc 'check', "The docker.daemon file is not created on installation and must be created. Ensure that daemon.json file ownership is set to root:root.

Execute the below command to verify that the file is owned and group-owned by root:

stat -c %U:%G /etc/docker/daemon.json 

If the docker.daemon file doesn't exist or if the file permissions are not set to root:root, this is a finding."
  desc 'fix', 'If docker.daemon does not exist, create the file and set the ownership and group-ownership for the file to root.

Run the following command:
chown root:root /etc/docker/daemon.json'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39086r627726_chk'
  tag severity: 'high'
  tag gid: 'V-235867'
  tag rid: 'SV-235867r627728_rule'
  tag stig_id: 'DKER-EE-005330'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39049r627727_fix'
  tag 'documentable'
  tag legacy: ['SV-104909', 'V-95771']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
