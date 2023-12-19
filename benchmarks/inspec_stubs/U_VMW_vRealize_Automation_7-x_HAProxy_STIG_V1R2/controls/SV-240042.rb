control 'SV-240042' do
  title 'HAProxy must be configured to use TLS for https connections.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

In order to protect the integrity and confidentiality of the remote sessions, HAProxy uses SSL/TLS.'
  desc 'check', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Verify that each frontend is configured with the following:

bind :<port> ssl crt <pemfile> ciphers FIPS:+3DES:!aNULL no-sslv3

Note: <port> and <pemfile> will be different for each frontend.

If "ssl" is not set for the bind option for each frontend, this is a finding.'
  desc 'fix', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Configure the bind option for each frontend with the "ssl" parameter.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43275r665293_chk'
  tag severity: 'medium'
  tag gid: 'V-240042'
  tag rid: 'SV-240042r879520_rule'
  tag stig_id: 'VRAU-HA-000020'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-43234r665294_fix'
  tag 'documentable'
  tag legacy: ['SV-100953', 'V-90303']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
