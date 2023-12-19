control 'SV-235806' do
  title 'Memory usage for all containers must be limited in Docker Enterprise.'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as memory limit, the amount of memory that a container may consume can be controlled.

By default, container can use all of the memory on the host. The user can use memory limit mechanism to prevent a denial of service arising from one container consuming all of the host’s resources such that other containers on the same host cannot perform their intended functions. Having no limit on memory can lead to issues where one container can easily make the whole system unstable, and as a result, unusable.

By default, all containers on a Docker host share the resources equally. No memory limits are enforced.'
  desc 'check', "Ensure memory limits are in place for all containers.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Memory={{ .HostConfig.Memory }}'

If the above command returns 0, it means the memory limits are not in place and this is a finding."
  desc 'fix', "Document container memory requirements in the System Security Plan (SSP).

Run the container with only as much memory as required. Always run the container using the --memory argument.

For example, run a container as below:

docker run --interactive --tty --memory 256m centos /bin/bash

In the above example, the container is started with a memory limit of 256 MB.

Note: The output of the below command would return values in scientific notation if memory limits are in place.

docker inspect --format='{{.Config.Memory}}' 7c5a2d4c7fe0

For example, if the memory limit is set to 256 MB for the above container instance, the output of the above command would be 2.68435456e+08 and NOT 256m. Convert this value using a scientific calculator or programmatic methods."
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39025r627543_chk'
  tag severity: 'medium'
  tag gid: 'V-235806'
  tag rid: 'SV-235806r627545_rule'
  tag stig_id: 'DKER-EE-002010'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38988r627544_fix'
  tag 'documentable'
  tag legacy: ['SV-104785', 'V-95647']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
