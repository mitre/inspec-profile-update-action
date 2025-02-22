control 'SV-235804' do
  title 'Only required ports must be open on the containers in Docker Enterprise.'
  desc 'Dockerfile for a container image defines the ports to be opened by default on a container instance. The list of ports may or may not be relevant to the application running within the container.

A container can be run just with the ports defined in the Dockerfile for its image or can be arbitrarily passed run time parameters to open a list of ports. Additionally, over time, Dockerfile may undergo various changes and the list of exposed ports may or may not be relevant to the application running within the container. Opening unneeded ports increase the attack surface of the container and the containerized application. As a recommended practice, do not open unneeded ports.

By default, all the ports that are listed in the Dockerfile under EXPOSE instruction for an image are opened when a container is run with -P or --publish-all flag.'
  desc 'check', "Ensure that mapped ports are the ones that are needed by the containers.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Ports={{ .NetworkSettings.Ports }}'

Review the list and ensure that the ports mapped are the ones that are really needed for the container. If there are any mapped ports that aren't documented by the System Security Plan (SSP), then this is a finding."
  desc 'fix', 'Document the ports required for each container in the SSP. 

Fix the Dockerfile of the container image to expose only needed ports by the containerized application. Ignore the list of ports defined in the Dockerfile by NOT using -P (UPPERCASE) or --publish-all flag when starting the container. Use the -p (lowercase) or --publish flag to explicitly define the ports needed for a particular container instance.

Example:
docker run --interactive --tty --publish 5000 --publish 5001 --publish 5002 centos /bin/bash'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39023r627537_chk'
  tag severity: 'medium'
  tag gid: 'V-235804'
  tag rid: 'SV-235804r627539_rule'
  tag stig_id: 'DKER-EE-001990'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38986r627538_fix'
  tag 'documentable'
  tag legacy: ['SV-104781', 'V-95643']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
