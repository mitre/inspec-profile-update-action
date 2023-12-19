control 'SV-235810' do
  title 'Mount propagation mode must not set to shared in Docker Enterprise.'
  desc 'Mount propagation mode allows mounting volumes in shared, slave or private mode on a container. Do not use shared mount propagation mode until needed.

A shared mount is replicated at all mounts and the changes made at any mount point are propagated to all mounts. Mounting a volume in shared mode does not restrict any other container to mount and make changes to that volume. This unintended volume changes could potentially impact data hosted on the mounted volume. Do not set mount propagation mode to shared until needed.

By default, the container mounts are private.'
  desc 'check', %q(Ensure mount propagation mode is not set to shared or rshared.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Propagation={{range $mnt := .Mounts}} {{json $mnt.Propagation}} {{end}}'

If Propagation=shared or Propagation-rshared, then this is a finding.)
  desc 'fix', 'Do not mount volumes in shared mode propagation.

For example, do not start container as below:

docker run <Run arguments> --volume=/hostPath:/containerPath:shared <Container Image Name or ID> <Command>'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39029r627555_chk'
  tag severity: 'medium'
  tag gid: 'V-235810'
  tag rid: 'SV-235810r627557_rule'
  tag stig_id: 'DKER-EE-002050'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38992r627556_fix'
  tag 'documentable'
  tag legacy: ['SV-104793', 'V-95655']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
