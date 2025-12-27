control 'SV-100949' do
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
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-89991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90299'
  tag rid: 'SV-100949r1_rule'
  tag stig_id: 'VRAU-HA-000010'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-97041r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
