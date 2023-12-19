control 'SV-235785' do
  title 'The Docker Enterprise hosts IPC namespace must not be shared.'
  desc "IPC (POSIX/SysV IPC) namespace provides separation of named shared memory segments, semaphores, and message queues. IPC namespace on the host thus should not be shared with the containers and should remain isolated.

IPC namespace provides separation of IPC between the host and containers. If the host's IPC namespace is shared with the container, it would allow processes within the container to see all of the IPC on the host system. This breaks the benefit of IPC level isolation between the host and the containers. Someone having access to the container can eventually manipulate the host IPC. Hence, do not share the host's IPC namespace with the containers.

Shared memory segments are used to accelerate inter-process communication. It is commonly used by high-performance applications. If such applications are containerized into multiple containers, the user might need to share the IPC namespace of the containers to achieve high performance. In such cases, the user should still be sharing container specific IPC namespaces only and not the host IPC namespace. The user may share the container's IPC namespace with another container as below:

Example:
docker run --interactive --tty --ipc=container:e3a7a1a97c58 centos /bin/bash

By default, all containers have the IPC namespace enabled and host IPC namespace is not shared with any container."
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Ensure the host's IPC namespace is not shared.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a UCP client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: IpcMode={{ .HostConfig.IpcMode }}'

If IpcMode="shareable", then the host's IPC namespace is shared and this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Do not start a container with --ipc=host argument. 

For example, do not start a container as below:

docker run --interactive --tty --ipc=host centos /bin/bash'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39004r627480_chk'
  tag severity: 'medium'
  tag gid: 'V-235785'
  tag rid: 'SV-235785r627482_rule'
  tag stig_id: 'DKER-EE-001250'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-38967r627481_fix'
  tag 'documentable'
  tag legacy: ['SV-104741', 'V-95603']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
