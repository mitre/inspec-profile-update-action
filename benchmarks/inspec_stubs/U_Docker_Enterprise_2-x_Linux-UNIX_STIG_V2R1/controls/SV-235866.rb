control 'SV-235866' do
  title 'Docker Enterprise socket file permissions must be set to 660 or more restrictive.'
  desc 'Verify that the Docker socket file has permissions of 660 or more restrictive.

Only root and members of docker group should be allowed to read and write to default Docker UNIX socket. Hence, the Docket socket file must have permissions of 660 or more restrictive.

By default, the permissions for Docker socket file is correctly set to 660.'
  desc 'check', 'Ensure that Docker socket file permissions are set to 660 or more restrictive.

Execute the below command to verify that the Docker socket file has permissions of 660 or more restrictive:

stat -c %a /var/run/docker.sock

If the permissions are not set to 660, this is a finding.'
  desc 'fix', 'chmod 660 /var/run/docker.sock

This sets the file permissions of the Docker socket file to 660.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39085r627723_chk'
  tag severity: 'high'
  tag gid: 'V-235866'
  tag rid: 'SV-235866r627725_rule'
  tag stig_id: 'DKER-EE-005320'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39048r627724_fix'
  tag 'documentable'
  tag legacy: ['SV-104907', 'V-95769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
