control 'SV-235800' do
  title 'SELinux security options must be set on Red Hat or CentOS systems for Docker Enterprise.'
  desc 'SELinux provides a Mandatory Access Control (MAC) system on RHEL and CentOS that greatly augments the default Discretionary Access Control (DAC) model. The user can thus add an extra layer of safety by enabling SELinux on the RHEL or CentOS host.

By default, no SELinux security options are applied on containers.'
  desc 'check', %q(This check only applies to the use of Docker Engine - Enterprise on either the Red Hat Enterprise Linux or CentOS host operating systems where SELinux is in use and should be executed on all nodes in a Docker Enterprise cluster.

Verify that the appropriate security options are configured for all running containers:

via CLI:

Linux: Execute the following command as a trusted user on the host operating system:

docker ps --quiet --all | xargs docker inspect --format '{{ .Name }}: SecurityOpt={{ .HostConfig.SecurityOpt }}' | grep -iv "ucp\|kube\|dtr"

If SecurityOpt=[label=disable], then this is a finding.)
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on either the Red Hat Enterprise Linux or CentOS host operating systems where SELinux is in use and should be executed on all nodes in a Docker Enterprise cluster.

Start the Docker daemon with SELinux mode enabled. Run Docker containers using appropriate security options.

via CLI:

Linux: Set the SE Linux state. Set the SELinux policy. Create or import a SELinux policy template for Docker containers. Start the Docker daemon with SELinux mode enabled by either adding the "--selinux-enabled" flag to the systemd drop-in file or by setting the "selinux-enabled" property to "true" in the "/etc/docker/daemon.json" daemon configuration file. Restart the Docker daemon.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39019r627525_chk'
  tag severity: 'medium'
  tag gid: 'V-235800'
  tag rid: 'SV-235800r627527_rule'
  tag stig_id: 'DKER-EE-001940'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38982r627526_fix'
  tag 'documentable'
  tag legacy: ['SV-104773', 'V-95635']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
