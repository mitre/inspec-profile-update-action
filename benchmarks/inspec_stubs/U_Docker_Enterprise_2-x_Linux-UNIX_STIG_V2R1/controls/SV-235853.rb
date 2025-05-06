control 'SV-235853' do
  title 'Docker Enterprise docker.socket file ownership must be set to root:root.'
  desc 'Verify that the docker.socket file ownership and group ownership is correctly set to root.

docker.socket file contains sensitive parameters that may alter the behavior of Docker remote API. Hence, it should be owned and group-owned by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable. By default, if the file is present, the ownership and group-ownership for this file is correctly set to root.'
  desc 'check', 'Ensure that docker.socket file ownership is set to root:root.

Step 1: Find out the file location:

systemctl show -p FragmentPath docker.socket

Step 2: If the file does not exist, this is not a finding. If the file exists, execute the below command with the correct file path to verify that the file is owned and group-owned by root.

Example:
stat -c %U:%G /usr/lib/systemd/system/docker.socket | grep -v root:root 

If the above command returns nothing, this is not a finding. If the command returns non root:root file permissions, this is a finding.'
  desc 'fix', 'Step 1: Find out the file location:

systemctl show -p FragmentPath docker.socket

Step 2: If the file exists, execute the below command with the correct file path to set the ownership and group ownership for the file to root.

Example:
chown root:root /usr/lib/systemd/system/docker.socket'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39072r627684_chk'
  tag severity: 'high'
  tag gid: 'V-235853'
  tag rid: 'SV-235853r627686_rule'
  tag stig_id: 'DKER-EE-005190'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39035r627685_fix'
  tag 'documentable'
  tag legacy: ['SV-104881', 'V-95743']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
