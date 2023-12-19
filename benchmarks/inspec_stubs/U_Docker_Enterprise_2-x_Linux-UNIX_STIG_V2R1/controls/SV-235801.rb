control 'SV-235801' do
  title 'Linux Kernel capabilities must be restricted within containers as defined in the System Security Plan (SSP) for Docker Enterprise.'
  desc "By default, Docker starts containers with a restricted set of Linux Kernel Capabilities. It means that any process may be granted the required capabilities instead of root access. Using Linux Kernel Capabilities, the processes do not have to run as root for almost all the specific areas where root privileges are usually needed. Docker supports the addition and removal of capabilities, allowing the use of a non-default profile. This may make Docker more secure through capability removal, or less secure through the addition of capabilities. It is thus recommended to remove all capabilities except those explicitly required for the user's container process.

By default, below capabilities are available for Linux containers:

AUDIT_WRITE
CHOWN
DAC_OVERRIDE
FOWNER
FSETID
KILL
MKNOD
NET_BIND_SERVICE
NET_RAW
SETFCAP
SETGID
SETPCAP
SETUID
SYS_CHROOT"
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Verify that the added and dropped Linux Kernel Capabilities are in line with the ones needed for container processes for each container instance as defined in the SSP.

via CLI:

Linux: Execute the following command as a trusted user on the host operating system:
docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'

If Linux Kernel Capabilities exceed what is defined in the SSP, then this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Document the required Kernel Capabilities for each container in the SSP. Only add needed capabilities when running containers. 

via CLI:

Linux: Execute the below command to add needed capabilities:

$> docker run --cap-add={"Capability 1","Capability 2"}

Execute the below command to drop unneeded capabilities:

$> docker run --cap-drop={"Capability 1","Capability 2"}

The user may also choose to drop all capabilities and add only add the needed ones as per the SSP:

$> docker run --cap-drop=all --cap-add={"Capability 1","Capability 2"}'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39020r627528_chk'
  tag severity: 'medium'
  tag gid: 'V-235801'
  tag rid: 'SV-235801r627530_rule'
  tag stig_id: 'DKER-EE-001950'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38983r627529_fix'
  tag 'documentable'
  tag legacy: ['SV-104775', 'V-95637']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
