control 'SV-235808' do
  title 'All Docker Enterprise containers root filesystem must be mounted as read only.'
  desc "The container's root filesystem should be treated as a 'golden image' by using Docker run's --read-only option. This prevents any writes to the container's root filesystem at container runtime and enforces the principle of immutable infrastructure.

Enabling this option forces containers at runtime to explicitly define their data writing strategy to persist or not persist their data. This also reduces security attack vectors since the container instance's filesystem cannot be tampered with or written to unless it has explicit read-write permissions on its filesystem folder and directories.

Enabling --read-only at container runtime may break some container OS packages if a data writing strategy is not defined. Define what the container's data should and should not persist at runtime to determine which recommendation procedure to utilize.

Example:

- Enable use --tmpfs for temporary file writes to /tmp
- Use Docker shared data volumes for persistent data writes

By default, a container will have its root filesystem writable allowing all container processes to write files owned by the container's runtime user."
  desc 'check', "Ensure all containers' root filesystem is mounted as read only.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs -L 1 docker inspect --format '{{ .Id }}: ReadonlyRootfs={{ .HostConfig.ReadonlyRootfs }}' 

 If ReadonlyRootfs=false, it means the container's root filesystem is writable and this is a finding."
  desc 'fix', %q(Add a --read-only flag at a container's runtime to enforce the container's root filesystem to be mounted as read only.

docker run <Run arguments> --read-only <Container Image Name or ID> <Command>

Enabling the --read-only option at a container's runtime should be used by administrators to force a container's executable processes to only write container data to explicit storage locations during the container's runtime.

Examples of explicit storage locations during a container's runtime include, but are not limited to:

1. Use the --tmpfs option to mount a temporary file system for non-persistent data writes.

Example:
docker run --interactive --tty --read-only --tmpfs "/run" --tmpfs "/tmp" [image] [command]

2. Enabling Docker rw mounts at a container's runtime to persist container data directly on the Docker host filesystem.

Example:
docker run --interactive --tty --read-only -v /opt/app/data:/run/app/data:rw [image] [command]

3. Utilizing Docker shared-storage volume plugins for Docker data volume to persist container data.

docker volume create -d convoy --opt o=size=20GB my-named-volume

docker run --interactive --tty --read-only -v my-named-volume:/run/app/data [image] [command])
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39027r627549_chk'
  tag severity: 'high'
  tag gid: 'V-235808'
  tag rid: 'SV-235808r627551_rule'
  tag stig_id: 'DKER-EE-002030'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38990r627550_fix'
  tag 'documentable'
  tag legacy: ['SV-104789', 'V-95651']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
