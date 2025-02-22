control 'SV-206799' do
  title 'The hardware Voice Video Endpoint must disable or restrict built-in web servers.'
  desc 'Hardware Voice Video Endpoints sometimes contain a web server for the implementation of various functions and features. In many cases these are used to configure the network settings or user preferences on the device. In some Voice Video Endpoints, a user can access a missed call list, call history, or other information. If access to such a web server is not restricted to authorized entities, the device supporting it is subject to unauthorized access and compromise.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable. If the hardware Voice Video Endpoint does not contain a web server, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint disables or restricts built-in web servers. Web servers embedded in hardware Voice Video Endpoints must be restricted to authorized entities’ devices through an authentication mechanism or, minimally, through IP address filtering, or be otherwise disabled. Additionally, the connection must be for direct user or administrative functions.

If the hardware Voice Video Endpoint does not disable or restrict built-in web servers, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to disable or restrict built-in web servers.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7055r363920_chk'
  tag severity: 'medium'
  tag gid: 'V-206799'
  tag rid: 'SV-206799r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00052'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7055r363921_fix'
  tag 'documentable'
  tag legacy: ['SV-81275', 'V-66785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
