control 'SRG-NET-000015-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint must be configured to prevent the configuration or display of configuration settings without the use of a PIN or password.'
  desc 'Many Unified Communications Endpoints can set or display configuration settings in the instrument itself. This presents a risk if a user obtains information such as the IP addresses and URLs of system components. This obtained information could be used to facilitate an attack on the system. Therefore, these devices should be considered a target to be defended against such individuals that would collect voice network information for illicit purposes. To mitigate information gathering by the adversaries, measures must be taken to protect this information.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to prevent the configuration or display of configuration settings without the use of a PIN or password.

If the Unified Communications Endpoint does not prevent the configuration or display of configuration settings without the use of a PIN or password, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to prevent the configuration or display of configuration settings without the use of a PIN or password.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000015-VVEP-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000015-VVEP-00101'
  tag rid: 'SRG-NET-000015-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000015-VVEP-00101'
  tag gtitle: 'SRG-NET-000015-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000015-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
