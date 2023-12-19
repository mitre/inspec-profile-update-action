control 'SV-235854' do
  title 'Docker Enterprise docker.socket file permissions must be set to 644 or more restrictive.'
  desc 'Verify that the docker.socket file permissions are correctly set to 644 or more restrictive.

docker.socket file contains sensitive parameters that may alter the behavior of Docker remote API. Hence, it should be writable only by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable. By default, if the file is present, the file permissions for this file are correctly set to 644.'
  desc 'check', 'Ensure that docker.socket file permissions are set to 644 or more restrictive.

Step 1: Find out the file location:

systemctl show -p FragmentPath docker.socket

Step 2: If the file does not exist, this is not a finding. If the file exists, execute the below command with the correct file path to verify that the file permissions are set to 644 or more restrictive.

stat -c %a /usr/lib/systemd/system/docker.socket

If the file permissions are not set to 644 or a more restrictive permission, this is a finding.'
  desc 'fix', 'Step 1: Find out the file location:

systemctl show -p FragmentPath docker.socket

Step 2: If the file exists, execute the below command with the correct file path to set the file permissions to 644.

Example:
chmod 644 /usr/lib/systemd/system/docker.socket'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39073r627687_chk'
  tag severity: 'medium'
  tag gid: 'V-235854'
  tag rid: 'SV-235854r627689_rule'
  tag stig_id: 'DKER-EE-005200'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39036r627688_fix'
  tag 'documentable'
  tag legacy: ['SV-104883', 'V-95745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
