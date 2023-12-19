control 'SV-235852' do
  title 'Docker Enterprise docker.service file permissions must be set to 644 or more restrictive.'
  desc 'Verify that the docker.service file permissions are correctly set to 644 or more restrictive.

docker.service file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should not be writable by any other user other than root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable. By default, if the file is present, the file permissions are correctly set to 644.'
  desc 'check', 'Ensure that docker.service file permissions are set to 644 or more restrictive.

Step 1: Find out the file location:

systemctl show -p FragmentPath docker.service

Step 2: If the file does not exist, this is not a finding. 

If the file exists, execute the below command with the correct file path to verify that the file permissions are set to 644 or more restrictive.

stat -c %a /usr/lib/systemd/system/docker.service

If the file permissions are not set to 644 or a more restrictive permission, this is a finding.'
  desc 'fix', 'Step 1: Find out the file location:

systemctl show -p FragmentPath docker.service

Step 2: If the file exists, execute the below command with the correct file path to set the file permissions to 644.

Example:
chmod 644 /usr/lib/systemd/system/docker.service'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39071r627681_chk'
  tag severity: 'medium'
  tag gid: 'V-235852'
  tag rid: 'SV-235852r627683_rule'
  tag stig_id: 'DKER-EE-005180'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39034r627682_fix'
  tag 'documentable'
  tag legacy: ['SV-104879', 'V-95741']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
