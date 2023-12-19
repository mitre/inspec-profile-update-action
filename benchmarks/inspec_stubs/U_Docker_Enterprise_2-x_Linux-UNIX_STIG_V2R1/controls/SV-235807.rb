control 'SV-235807' do
  title 'Docker Enterprise CPU priority must be set appropriately on all containers.'
  desc 'By default, all containers on a Docker host share the resources equally. By using the resource management capabilities of Docker host, such as CPU shares, the user control the host CPU resources that a container may consume.

By default, CPU time is divided between containers equally. If it is desired, to control the CPU time amongst the container instances, use CPU sharing feature. CPU sharing allows to prioritize one container over the other and forbids the lower priority container to claim CPU resources more often. This ensures that the high priority containers are served better.

If CPU shares are not properly set, the container process may have to starve if the resources on the host are not available. If the CPU resources on the host are free, CPU shares do not place any restrictions on the CPU that the container may use.

By default, all containers on a Docker host share the resources equally. No CPU shares are enforced.'
  desc 'check', "Ensure CPU shares are in place for all containers.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CpuShares={{ .HostConfig.CpuShares }}'

If the above command returns 0 or 1024, it means the CPU shares are not in place and this is a finding."
  desc 'fix', 'Document container CPU requirements in the System Security Plan (SSP). 

Manage the CPU shares between containers. To do so, start the container using the --cpu-shares argument.

For example, run a container as below:

docker run --interactive --tty --cpu-shares 512 [image] [command]

In the above example, the container is started with CPU shares of 50% of what the other containers use. So, if the other container has CPU shares of 80%, this container will have CPU shares of 40%.

Note: Every new container will have 1024 shares of CPU by default. However, this value is shown as 0 if running the command mentioned in the audit section.

Alternatively,

1. Navigate to /sys/fs/cgroup/cpu/system.slice/ directory.
2. Check the container instance ID using docker ps.
3. Now, inside the above directory (in step 1), there will be a directory by name docker-<Instance ID>.scope. For example, docker-4acae729e8659c6be696ee35b2237cc1fe4edd2672e9186434c5116e1a6fbed6.scope. Navigate to this directory.
4. Find a file named cpu.shares. Execute cat cpu.shares. This will always show the CPU share value based on the system. So, even if there is no CPU shares configured using -c or --cpu-shares argument in the docker run command, this file will have a value of 1024.

By setting one container’s CPU shares to 512, it will receive half of the CPU time compared to the other container. So, take 1024 as 100% and then do quick math to derive the number that set for respective CPU shares. For example, use 512 to set 50% and 256 to set 25%.'
  impact 0.3
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39026r627546_chk'
  tag severity: 'low'
  tag gid: 'V-235807'
  tag rid: 'SV-235807r627548_rule'
  tag stig_id: 'DKER-EE-002020'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38989r627547_fix'
  tag 'documentable'
  tag legacy: ['SV-104787', 'V-95649']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
