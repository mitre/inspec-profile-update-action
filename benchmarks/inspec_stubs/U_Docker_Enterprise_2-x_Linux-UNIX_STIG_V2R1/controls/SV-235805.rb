control 'SV-235805' do
  title 'Docker Enterprise hosts network namespace must not be shared.'
  desc %q(The networking mode on a container when set to --net=host, skips placing the container inside separate network stack. In essence, this choice tells Docker to not containerize the container's networking. This would network-wise mean that the container lives "outside" in the main Docker host and has full access to its network interfaces.

This is potentially dangerous. It allows the container process to open low-numbered ports like any other root process. It also allows the container to access network services like D-bus on the Docker host. Thus, a container process can potentially do unexpected things such as shutting down the Docker host. Do not use this option.

By default, container connects to Docker bridge.)
  desc 'check', %q(Ensure the host's network namespace is not shared.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}'

If the above command returns NetworkMode=host, this is a finding.)
  desc 'fix', 'Do not pass --net=host or --network=host options when starting the container.

For example, when executing docker run, do not use the --net=host nor --network=host arguments.

A more detailed reference for the docker run command can be found at https://docs.docker.com/engine/reference/run/.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39024r627540_chk'
  tag severity: 'high'
  tag gid: 'V-235805'
  tag rid: 'SV-235805r627542_rule'
  tag stig_id: 'DKER-EE-002000'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38987r627541_fix'
  tag 'documentable'
  tag legacy: ['SV-104783', 'V-95645']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
