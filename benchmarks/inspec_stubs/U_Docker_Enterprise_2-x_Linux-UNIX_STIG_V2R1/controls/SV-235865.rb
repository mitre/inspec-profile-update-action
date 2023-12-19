control 'SV-235865' do
  title 'Docker Enterprise socket file ownership must be set to root:docker.'
  desc 'Verify that the Docker socket file is owned by root and group-owned by docker.

Docker daemon runs as root. The default UNIX socket hence must be owned by root. If any other user or process owns this socket, then it might be possible for that non-privileged user or process to interact with Docker daemon. Also, such a non-privileged user or process might interact with containers. This is neither secure nor desired behavior.

Additionally, the Docker installer creates a UNIX group called docker. Users can be added to this group, and then those users would be able to read and write to default Docker UNIX socket. The membership to the docker group is tightly controlled by the system administrator. If any other group owns this socket, then it might be possible for members of that group to interact with Docker daemon. Also, such a group might not be as tightly controlled as the docker group. This is neither secure nor desired behavior.

Hence, the default Docker UNIX socket file must be owned by root and group-owned by docker to maintain the integrity of the socket file.

By default, the ownership and group-ownership for Docker socket file is correctly set to root:docker.'
  desc 'check', 'Ensure that Docker socket file ownership is set to root:docker.

Execute the below command to verify that the Docker socket file is owned by root and group-owned by docker:

stat -c %U:%G /var/run/docker.sock 

If docker.sock file ownership is not set to root:docker, this is a finding.'
  desc 'fix', 'chown root:docker /var/run/docker.sock

This sets the ownership to root and group-ownership to docker for default Docker socket file.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39084r627720_chk'
  tag severity: 'high'
  tag gid: 'V-235865'
  tag rid: 'SV-235865r627722_rule'
  tag stig_id: 'DKER-EE-005310'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39047r627721_fix'
  tag 'documentable'
  tag legacy: ['SV-104905', 'V-95767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
