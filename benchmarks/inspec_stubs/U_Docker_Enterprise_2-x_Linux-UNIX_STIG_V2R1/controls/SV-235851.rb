control 'SV-235851' do
  title 'Docker Enterprise docker.service file ownership must be set to root:root.'
  desc 'Verify that the docker.service file ownership and group-ownership are correctly set to root.

docker.service file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should be owned and group-owned by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable. By default, if the file is present, the ownership and group-ownership for this file is correctly set to root.'
  desc 'check', 'Ensure that docker.service file ownership is set to root:root

Step 1: Find out the file location:

systemctl show -p FragmentPath docker.service

Step 2: If the file does not exist, this is not a finding. If the file exists, execute the below command with the correct file path to verify that the file is owned and group-owned by root.

Example:
stat -c %U:%G /usr/lib/systemd/system/docker.service | grep -v root:root 

If the above command returns nothing, this is not a finding. If the command returns non root:root file permissions, this is a finding.'
  desc 'fix', 'Step 1: Find out the file location:

systemctl show -p FragmentPath docker.service

Step 2: If the file exists, execute the below command with the correct file path to set the ownership and group ownership for the file to root.

Example:
chown root:root /usr/lib/systemd/system/docker.service'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39070r627678_chk'
  tag severity: 'high'
  tag gid: 'V-235851'
  tag rid: 'SV-235851r627680_rule'
  tag stig_id: 'DKER-EE-005170'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39033r627679_fix'
  tag 'documentable'
  tag legacy: ['SV-104877', 'V-95739']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
