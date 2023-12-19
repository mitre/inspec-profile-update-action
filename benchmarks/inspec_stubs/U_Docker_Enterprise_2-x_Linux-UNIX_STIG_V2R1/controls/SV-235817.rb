control 'SV-235817' do
  title 'The Docker Enterprise hosts user namespace must not be shared.'
  desc "Do not share the host's user namespaces with the containers.

User namespaces ensure that a root process inside the container will be mapped to a non-root process outside the container. Sharing the user namespaces of the host with the container thus does not isolate users on the host with users on the containers.

By default, the host user namespace is shared with the containers until user namespace support is enabled."
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure PIDs cgroup limit is used.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UsernsMode={{ .HostConfig.UsernsMode }}'

Ensure that it does not return any value for UsernsMode. If it returns a value of host, it means the host user namespace is shared with the containers and this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not share user namespaces between host and containers.

For example, do not run a container as below:

docker run --rm -it --userns=host <image>'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39036r627576_chk'
  tag severity: 'high'
  tag gid: 'V-235817'
  tag rid: 'SV-235817r627578_rule'
  tag stig_id: 'DKER-EE-002120'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38999r627577_fix'
  tag 'documentable'
  tag legacy: ['SV-104807', 'V-95669']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
