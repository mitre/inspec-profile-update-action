control 'SV-235870' do
  title 'Docker Enterprise /etc/default/docker file permissions must be set to 644 or more restrictive.'
  desc 'Verify that the /etc/default/docker file permissions are correctly set to 644 or more restrictive.

/etc/default/docker file contains sensitive parameters that may alter the behavior of docker daemon. Hence, it should be writable only by root to maintain the integrity of the file.

This file may not be present on the system. In that case, this recommendation is not applicable.'
  desc 'check', 'This requirement applies to Ubuntu Linux systems only. 

Ensure that /etc/default/docker file permissions are set to 644 or more restrictive.

Execute the below command to verify that the file permissions are correctly set to 644 or more restrictive:

stat -c %a /etc/default/docker

If the permissions are not set to 644, this is a finding.'
  desc 'fix', 'Set the file permissions for this file to 644.

Run the following command:
chmod 644 /etc/default/docker'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39089r627735_chk'
  tag severity: 'high'
  tag gid: 'V-235870'
  tag rid: 'SV-235870r627737_rule'
  tag stig_id: 'DKER-EE-005360'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39052r627736_fix'
  tag 'documentable'
  tag legacy: ['SV-104915', 'V-95777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
