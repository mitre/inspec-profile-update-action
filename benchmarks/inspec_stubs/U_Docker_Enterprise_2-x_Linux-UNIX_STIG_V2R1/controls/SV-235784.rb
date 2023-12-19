control 'SV-235784' do
  title 'The Docker Enterprise hosts process namespace must not be shared.'
  desc "Process ID (PID) namespaces isolate the PID number space, meaning that processes in different PID namespaces can have the same PID. This is process level isolation between containers and the host.

PID namespace provides separation of processes. The PID Namespace removes the view of the system processes, and allows process IDs to be reused including PID 1. If the host's PID namespace is shared with the container, it would allow processes within the container to see all of the processes on the host system. This breaks the benefit of process level isolation between the host and the containers. Someone having access to the container can eventually know all the processes running on the host system and can even kill the host system processes from within the container. Hence, do not share the host's process namespace with the containers.

Container processes cannot see the processes on the host system. In certain cases, the container should share the host's process namespace. For example, the user could build a container with debugging tools like strace or gdb, but want to use these tools when debugging processes within the container. If this is desired, then share only one (or needed) host process by using the -p switch.

Example:
docker run --pid=host rhel7 strace -p 1234

By default, all containers have the PID namespace enabled and the host's process namespace is not shared with the containers."
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Ensure the host's process namespace is not shared.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a UCP client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: PidMode={{ .HostConfig.PidMode }}'

If PidMode = "host", it means the host PID namespace is shared with the container and this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not start a container with --pid=host argument.

For example, do not start a container as below:

docker run --interactive --tty --pid=host centos /bin/bash'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39003r627477_chk'
  tag severity: 'medium'
  tag gid: 'V-235784'
  tag rid: 'SV-235784r627479_rule'
  tag stig_id: 'DKER-EE-001240'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-38966r627478_fix'
  tag 'documentable'
  tag legacy: ['SV-104739', 'V-95601']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
