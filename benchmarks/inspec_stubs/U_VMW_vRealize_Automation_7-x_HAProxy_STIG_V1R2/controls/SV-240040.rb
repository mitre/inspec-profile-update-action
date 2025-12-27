control 'SV-240040' do
  title 'HAProxy must enable cookie-based persistence in a backend.'
  desc 'Session management is the practice of protecting the bulk of the user authorization and identity information. As a load balancer, HAProxy must participate in session management in order to set the session management cookie. Additionally, HAProxy must also ensure that the backend server which started the session with the client is forwarded subsequent requests from the client.'
  desc 'check', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Verify that each backend is configured with the following:

cookie JSESSIONID prefix

If "cookie" is not set for each backend, this is a finding.'
  desc 'fix', "Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Configure each backend with the following value:

'cookie JSESSIONID prefix'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43273r665287_chk'
  tag severity: 'medium'
  tag gid: 'V-240040'
  tag rid: 'SV-240040r879511_rule'
  tag stig_id: 'VRAU-HA-000010'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-43232r665288_fix'
  tag 'documentable'
  tag legacy: ['SV-100949', 'V-90299']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
