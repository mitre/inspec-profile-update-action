control 'SV-235819' do
  title 'Docker Enterprise privileged ports must not be mapped within containers.'
  desc 'The TCP/IP port numbers below 1024 are considered privileged ports. Normal users and processes are not allowed to use them for various security reasons. Docker allows a container port to be mapped to a privileged port.

By default, if the user does not specifically declare the container port to host port mapping, Docker automatically and correctly maps the container port to one available in 49153-65535 block on the host. But, Docker allows a container port to be mapped to a privileged port on the host if the user explicitly declared it. This is so because containers are executed with NET_BIND_SERVICE Linux kernel capability that does not restrict the privileged port mapping. The privileged ports receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.'
  desc 'check', "This check should be executed on all nodes in a Docker Enterprise cluster.

Verify that no running containers are mapping host port numbers below 1024.

via CLI:

Linux: Execute the following command as a trusted user on the host operating system:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'

Review the list and ensure that container ports are not mapped to host port numbers below 1024. If they are, then this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise.

Do not map the container ports to privileged host ports when starting a container. Also, ensure that there is no such container to host privileged port mapping declarations in the Dockerfile.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39038r627582_chk'
  tag severity: 'high'
  tag gid: 'V-235819'
  tag rid: 'SV-235819r627584_rule'
  tag stig_id: 'DKER-EE-002150'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-39001r627583_fix'
  tag 'documentable'
  tag legacy: ['SV-104811', 'V-95673']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
