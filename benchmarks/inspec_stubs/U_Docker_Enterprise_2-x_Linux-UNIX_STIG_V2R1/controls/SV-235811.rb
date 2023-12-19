control 'SV-235811' do
  title 'The Docker Enterprise hosts UTS namespace must not be shared.'
  desc 'UTS namespaces provide isolation of two system identifiers: the hostname and the NIS domain name. It is used for setting the hostname and the domain that is visible to running processes in that namespace. Processes running within containers do not typically require to know hostname and domain name. Hence, the namespace should not be shared with the host.

Sharing the UTS namespace with the host provides full permission to the container to change the hostname of the host. This must not be allowed.

By default, all containers have the UTS namespace enabled and host UTS namespace is not shared with any container.'
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure the host's UTS namespace is not shared.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: UTSMode={{ .HostConfig.UTSMode }}' 

If the above command returns host, it means the host UTS namespace is shared with the container and this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not start a container with --uts=host argument.

For example, do not start a container as below:

docker run --rm --interactive --tty --uts=host rhel7.2'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39030r627558_chk'
  tag severity: 'medium'
  tag gid: 'V-235811'
  tag rid: 'SV-235811r627560_rule'
  tag stig_id: 'DKER-EE-002060'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38993r627559_fix'
  tag 'documentable'
  tag legacy: ['SV-104795', 'V-95657']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
