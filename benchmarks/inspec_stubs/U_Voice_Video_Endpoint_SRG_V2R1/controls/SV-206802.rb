control 'SV-206802' do
  title 'The hardware Voice Video Endpoint must not use the default PIN or password to access configuration and display of network IP settings.'
  desc 'Many Voice Video Endpoints can set or display configuration settings in the instrument itself. This presents a risk if a user obtains information such as the IP addresses and URLs of system components. This obtained information could be used to facilitate an attack on the system. Therefore these devices should be considered a target to be defended against individuals that would collect voice network information for illicit purposes. To mitigate information gathering by the adversaries, measures must be taken to protect this information.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint does not use the default PIN or password to access configuration and display of network IP settings.

If the hardware Voice Video Endpoint uses the default PIN or password to access configuration and display of network IP settings, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to not use the default PIN or password to access configuration and display of network IP settings.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7058r363929_chk'
  tag severity: 'medium'
  tag gid: 'V-206802'
  tag rid: 'SV-206802r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00055'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7058r363930_fix'
  tag 'documentable'
  tag legacy: ['SV-81281', 'V-66791']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
