control 'SV-235868' do
  title 'Docker Enterprise daemon.json file permissions must be set to 644 or more restrictive.'
  desc 'Verify that the daemon.json file permissions are correctly set to 644 or more restrictive.

daemon.json file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be writable only by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable.'
  desc 'check', 'The docker.daemon file is not created on installation and must be created. Ensure that daemon.json file permissions are set to 644 or more restrictive.

Execute the below command to verify that the file permissions are correctly set to 644 or more restrictive:

stat -c %a /etc/docker/daemon.json

If the permissions are not set to 644 or a more restrictive setting, this is a finding.

If the permissions are not set to 644, this is a finding.'
  desc 'fix', 'If docker.daemon does not exist, create the file and set the file permissions for this file to 644.

Run the following command;
chmod 644 /etc/docker/daemon.json'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39087r627729_chk'
  tag severity: 'high'
  tag gid: 'V-235868'
  tag rid: 'SV-235868r627731_rule'
  tag stig_id: 'DKER-EE-005340'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39050r627730_fix'
  tag 'documentable'
  tag legacy: ['SV-104911', 'V-95773']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
