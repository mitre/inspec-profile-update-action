control 'SV-233074' do
  title 'The container platform runtime must enforce the use of ports that are non-privileged.'
  desc 'Privileged ports are those ports below 1024 and that require system privileges for their use. If containers are able to use these ports, the container must be run as a privileged user. The container platform must stop containers that try to map to these ports directly. Allowing non-privileged ports to be mapped to the container-privileged port is the allowable method when a certain port is needed. An example is mapping port 8080 externally to port 80 in the container.'
  desc 'check', 'Review the container platform configuration and the containers within the platform by performing the following checks:

1. Verify the container platform is configured to disallow the use of privileged ports by containers.
2. Validate all containers within the container platform are using non-privileged ports.
3. Attempt to instantiate a container image that uses a privileged port.

If the container platform is not configured to disallow the use of privileged ports, this is a finding.

If the container platform has containers using privileged ports, this is a finding.

If the container platform allows containers to be instantiated that use privileged ports, this is a finding.'
  desc 'fix', 'Configure the container platform to disallow the use of privileged ports by containers. Move any containers that are using privileged ports to non-privileged ports.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36010r601706_chk'
  tag severity: 'medium'
  tag gid: 'V-233074'
  tag rid: 'SV-233074r879588_rule'
  tag stig_id: 'SRG-APP-000142-CTR-000330'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-35978r600710_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
