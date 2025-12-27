control 'SV-235802' do
  title 'Privileged Linux containers must not be used for Docker Enterprise.'
  desc 'Using the --privileged flag gives all Linux Kernel Capabilities to the container thus overwriting the --cap-add and --cap-drop flags. Ensure that it is not used. The --privileged flag gives all capabilities to the container, and it also lifts all the limitations enforced by the device cgroup controller. In other words, the container can then do almost everything that the host can do. This flag exists to allow special use-cases, like running Docker within Docker.'
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Verify that no containers are running with the --privileged flag. The --privileged flag provides full kernel capabilities. Capabilities must be specified in the System Security Plan (SSP) rather than allowing full privileges.

via CLI:

Linux: Execute the following command as a trusted user on the host operating system:

docker ps --quiet --all | grep -iv "ucp\|kube\|dtr" | awk '{print $1}' | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'

Verify in the output that no containers are running with the --privileged flag. If there are, then this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Do not run containers with the --privileged flag.

For example, do not start a container as below:

docker run --interactive --tty --privileged centos /bin/bash'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39021r672377_chk'
  tag severity: 'medium'
  tag gid: 'V-235802'
  tag rid: 'SV-235802r672378_rule'
  tag stig_id: 'DKER-EE-001960'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38984r627532_fix'
  tag 'documentable'
  tag legacy: ['SV-104777', 'V-95639']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
