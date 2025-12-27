control 'SV-235803' do
  title 'SSH must not run within Linux containers for Docker Enterprise.'
  desc 'SSH server should not be running within the container. The user should instead use Universal Control Plane (UCP) to console in to running containers.

Running SSH within the container increases the complexity of security management by making it:

- Difficult to manage access policies and security compliance for SSH server
- Difficult to manage keys and passwords across various containers
- Difficult to manage security upgrades for SSH server
- It is possible to have shell access to a container without using SSH, the needlessly increasing the complexity of security management should be avoided

By default, SSH server is not running inside the container. Only one process per container is allowed.'
  desc 'check', 'This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Verify that no running containers have a process for SSH server.

via CLI:

for i in $(docker ps -qa); do echo $i; docker exec $i ps -el | grep -i sshd;done

Container not running errors are not a finding.

If running containers have a process for SSH server, this is a finding.'
  desc 'fix', "This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Remove SSH packages from all Docker base images in use in the user's environment."
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39022r627534_chk'
  tag severity: 'medium'
  tag gid: 'V-235803'
  tag rid: 'SV-235803r627536_rule'
  tag stig_id: 'DKER-EE-001970'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38985r627535_fix'
  tag 'documentable'
  tag legacy: ['SV-104779', 'V-95641']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
