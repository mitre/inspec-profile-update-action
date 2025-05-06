control 'SV-235816' do
  title 'All Docker Enterprise containers must be restricted from acquiring additional privileges.'
  desc 'Restrict the container from acquiring additional privileges via suid or sgid bits.

A process can set the no_new_priv bit in the kernel. It persists across fork, clone, and execve. The no_new_priv bit ensures that the process or its children processes do not gain any additional privileges via suid or sgid bits. This way a lot of dangerous operations become a lot less dangerous because there is no possibility of subverting privileged binaries.

no_new_priv prevents LSMs like SELinux from transitioning to process labels that have access not allowed to the current process.

By default, new privileges are not restricted.'
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Ensure all containers are restricted from acquiring additional privileges.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs -L 1 docker inspect --format '{{ .Id }}: SecurityOpt={{ .HostConfig.SecurityOpt }}'

The above command returns the security options currently configured for the running containers, if 'SecurityOpt=' setting does not include the 'no-new-privileges' flag, this is a finding.")
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Start the containers as below:

docker run --rm -it --security-opt=no-new-privileges <image>

A reference for the docker run command can be found at https://docs.docker.com/engine/reference/run/.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39035r672379_chk'
  tag severity: 'high'
  tag gid: 'V-235816'
  tag rid: 'SV-235816r672380_rule'
  tag stig_id: 'DKER-EE-002110'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38998r627574_fix'
  tag 'documentable'
  tag legacy: ['SV-104805', 'V-95667']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
