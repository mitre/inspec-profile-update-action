control 'SV-233185' do
  title 'The container platform runtime must prohibit the instantiation of container images without explicit privileged status.'
  desc 'Controlling access to those users and roles responsible for container image instantiation reduces the risk of untested or potentially malicious containers from being executed within the platform and on the hosting system. This access may be separate from the access required to install container images into the registry and those access requirements required to perform patch management and upgrades within the container platform. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.'
  desc 'check', 'Review the container platform runtime configuration to determine if only accounts given specific container instantiation privileges can execute the container image instantiation process. 

Attempt to instantiate a container image using an account that does not have the proper privileges to execute the process. 

If container images can be instantiated using an account without the proper privileges, this is a finding.'
  desc 'fix', 'Configure the container platform runtime to prohibit the instantiation of container images without explicit container image instantiation privileges given to users.'
  impact 0.7
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36121r601791_chk'
  tag severity: 'high'
  tag gid: 'V-233185'
  tag rid: 'SV-233185r601792_rule'
  tag stig_id: 'SRG-APP-000378-CTR-000885'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-36089r601043_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
