control 'SV-235828' do
  title 'PIDs cgroup limits must be used in Docker Enterprise.'
  desc 'Use --pids-limit flag at container runtime.

Attackers could launch a fork bomb with a single command inside the container. This fork bomb can crash the entire system and requires a restart of the host to make the system functional again. PIDs cgroup --pids-limit will prevent this kind of attacks by restricting the number of forks that can happen inside a container at a given time.

The Default value for --pids-limit is 0 which means there is no restriction on the number of forks. Also, note that PIDs cgroup limit works only for the kernel versions 4.3+.'
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Ensure PIDs cgroup limit is used.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: PidsLimit={{ .HostConfig.PidsLimit }}'

Ensure that PidsLimit is not set to 0 or -1. A PidsLimit of 0 or -1 means that any number of processes can be forked inside the container concurrently. If the PidsLimit is set to either 0 or -1 then this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Use --pids-limit flag while launching the container with an appropriate value.

Example:
docker run -it --pids-limit 100 <Image_ID>
In the above example, the number of processes allowed to run at any given time is set to 100. After a limit of 100 concurrently running processes is reached, docker would restrict any new process creation.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39047r627609_chk'
  tag severity: 'medium'
  tag gid: 'V-235828'
  tag rid: 'SV-235828r627611_rule'
  tag stig_id: 'DKER-EE-002780'
  tag gtitle: 'SRG-APP-000247'
  tag fix_id: 'F-39010r627610_fix'
  tag 'documentable'
  tag legacy: ['SV-104827', 'V-95689']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
