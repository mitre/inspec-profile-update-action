control 'SV-235844' do
  title 'The Docker Enterprise default ulimit must not be overwritten at runtime unless approved in the System Security Plan (SSP).'
  desc 'The default ulimit is set at the Docker daemon level. However, override the default ulimit setting, if needed, during container runtime.

ulimit provides control over the resources available to the shell and to processes started by it. Setting system resource limits judiciously prevents many disasters such as a fork bomb. Sometimes, even friendly users and legitimate processes can overuse system resources and in-turn can make the system unusable.

The default ulimit set at the Docker daemon level should be honored. If the default ulimit settings are not appropriate for a particular container instance, override them as an exception. But, do not make this a practice. If most of the container instances are overriding default ulimit settings, consider changing the default ulimit settings to something that is appropriate for your needs.

If the ulimits are not set properly, the desired resource control might not be achieved and might even make the system unusable.

Container instances inherit the default ulimit settings set at the Docker daemon level.'
  desc 'check', "This check only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Ensure the default ulimit is not overwritten at runtime unless approved in the SSP.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Ulimits={{ .HostConfig.Ulimits }}'

If each container instance returns Ulimits=<no value>, this is not a finding.

If a container sets a Ulimit and the setting is not approved in the SSP, this is a finding."
  desc 'fix', 'This fix only applies to the use of Docker Engine - Enterprise on a Linux host operating system.

Only override the default ulimit settings if needed and if so, document these settings in the SSP.

For example, to override default ulimit settings start a container as below:

docker run --ulimit nofile=1024:1024 --interactive --tty [image] [command]'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39063r627657_chk'
  tag severity: 'medium'
  tag gid: 'V-235844'
  tag rid: 'SV-235844r627659_rule'
  tag stig_id: 'DKER-EE-004040'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-39026r627658_fix'
  tag 'documentable'
  tag legacy: ['SV-104861', 'V-95723']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
