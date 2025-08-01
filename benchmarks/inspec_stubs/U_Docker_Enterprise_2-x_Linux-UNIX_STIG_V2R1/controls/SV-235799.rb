control 'SV-235799' do
  title 'An appropriate AppArmor profile must be enabled on Ubuntu systems for Docker Enterprise.'
  desc "AppArmor protects the Ubuntu OS and applications from various threats by enforcing security policy which is also known as AppArmor profile. The user can create their own AppArmor profile for containers or use the Docker's default AppArmor profile. This would enforce security policies on the containers as defined in the profile.

By default, docker-default AppArmor profile is applied for running containers and this profile can be found at /etc/apparmor.d/docker."
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on the Ubuntu host operating system and should be executed on all nodes in a Docker Enterprise cluster.

Verify that all running containers include a valid AppArmor profile:

via CLI:

Linux: Execute the following command as a trusted user on the host operating system:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: AppArmorProfile={{ .AppArmorProfile }}'

Verify that all containers include a valid AppArmor Profile in the output. If they do not, then this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on the Ubuntu host operating system where AppArmor is in use and should be executed on all nodes in a Docker Enterprise cluster.

Run all containers using an AppArmor profile:

via CLI:

Linux: Install AppArmor (if not already installed).

Create/import an AppArmor profile (if not using the "docker-default" profile). Put the profile in "enforcing" model. Execute the following command as a trusted user on the host operating system to run the container using the customized AppArmor profile:

docker run [options] --security-opt="apparmor:[PROFILENAME]" [image] [command]

If using the "docker-default" default profile, run the container using the following command instead:

docker run [options] --security-opt apparmor=docker-default [image] [command]'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39018r627522_chk'
  tag severity: 'medium'
  tag gid: 'V-235799'
  tag rid: 'SV-235799r627524_rule'
  tag stig_id: 'DKER-EE-001930'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38981r627523_fix'
  tag 'documentable'
  tag legacy: ['SV-104769', 'V-95631']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
