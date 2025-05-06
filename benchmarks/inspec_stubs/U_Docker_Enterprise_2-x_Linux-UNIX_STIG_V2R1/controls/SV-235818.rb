control 'SV-235818' do
  title 'The Docker Enterprise socket must not be mounted inside any containers.'
  desc 'The docker socket docker.sock (Linux) and \\\\.\\pipe\\docker_engine (Windows) should not be mounted inside a container, with the exception case being during the installation of Universal Control Plane (UCP) component of Docker Enterprise as it is required for install.

If the docker socket is mounted inside a container it would allow processes running within the container to execute docker commands which effectively allows for full control of the host.

By default, docker.sock (linux) and \\\\.\\pipe\\docker_engine (windows) is not mounted inside containers.'
  desc 'check', %q(This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

As a Docker EE Admin, execute the following command using a UCP client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Mounts }}' | grep -i "docker.sock\|docker_engine"

If the Docker socket is mounted inside containers, this is a finding.)
  desc 'fix', 'When using the -v/--volume flags to mount volumes to containers in a docker run command, do not use docker.sock as a volume.

A reference for the docker run command can be found at https://docs.docker.com/engine/reference/run/.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39037r627579_chk'
  tag severity: 'high'
  tag gid: 'V-235818'
  tag rid: 'SV-235818r627581_rule'
  tag stig_id: 'DKER-EE-002130'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-39000r627580_fix'
  tag 'documentable'
  tag legacy: ['SV-104809', 'V-95671']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
