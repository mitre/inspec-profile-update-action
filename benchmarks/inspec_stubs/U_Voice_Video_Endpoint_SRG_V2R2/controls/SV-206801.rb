control 'SV-206801' do
  title 'The hardware Voice Video Endpoint must prevent the display of network IP settings without the use of a PIN or password.'
  desc 'Many Voice Video Endpoints can set or display configuration settings in the instrument itself. This presents a risk if a user obtains information such as the IP addresses and URLs of system components. This obtained information could be used to facilitate an attack on the system. Therefore these devices should be considered a target to be defended against such individuals that would collect voice network information for illicit purposes. To mitigate information gathering by the adversaries, measures must be taken to protect this information.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint prevents the display of network IP settings without the use of a PIN or password.

If the hardware Voice Video Endpoint does not prevent the display of network IP settings without the use of a PIN or password, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to prevent the display of network IP settings without the use of a PIN or password.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7057r363926_chk'
  tag severity: 'medium'
  tag gid: 'V-206801'
  tag rid: 'SV-206801r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00054'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7057r363927_fix'
  tag 'documentable'
  tag legacy: ['V-66789', 'SV-81279']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
