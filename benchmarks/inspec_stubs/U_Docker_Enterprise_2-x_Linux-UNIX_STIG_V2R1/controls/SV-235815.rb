control 'SV-235815' do
  title 'cgroup usage must be confirmed in Docker Enterprise.'
  desc 'It is possible to attach to a particular cgroup on container run. Confirming cgroup usage would ensure that containers are running under defined cgroups.

System administrators typically define cgroups under which containers are supposed to run. Even if cgroups are not explicitly defined by the system administrators, containers run under docker cgroup by default. At run-time, it is possible to attach to a different cgroup other than the one that was expected to be used. This usage should be monitored and confirmed. By attaching to a different cgroup than the one that is expected, excess permissions and resources might be granted to the container and thus, can prove to be unsafe.

By default, containers run under docker cgroup.'
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure cgroup usage is confirmed.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CgroupParent={{ .HostConfig.CgroupParent }}' 

If the cgroup is blank, the container is running under default docker cgroup. If the containers are found to be running under cgroup other than the one that is documented in the System Security Plan (SSP), then this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not use --cgroup-parent option in docker run command unless needed.
If required, document cgroup usage in the SSP.

A reference for the docker run command can be found at https://docs.docker.com/engine/reference/run/.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39034r627570_chk'
  tag severity: 'medium'
  tag gid: 'V-235815'
  tag rid: 'SV-235815r627572_rule'
  tag stig_id: 'DKER-EE-002100'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38997r627571_fix'
  tag 'documentable'
  tag legacy: ['SV-104803', 'V-95665']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
