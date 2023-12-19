control 'SV-99831' do
  title 'HAProxy must set an absolute timeout on sessions.'
  desc "Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to re-authenticate guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the web server or an attacker using a hijacked session to slowly probe the web server.

HAProxy provides a 'tune.ssl.lifetime' parameter, which will set an absolute timeout on SSL sessions."
  desc 'check', "At the command prompt, execute the following command:

grep 'tune.ssl.lifetime' /etc/haproxy/haproxy.cfg

If the command returns any value, this is a finding."
  desc 'fix', %q(Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to the "globals" section

Add the value 'tune.ssl.lifetime 20m')
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89181'
  tag rid: 'SV-99831r1_rule'
  tag stig_id: 'VRAU-HA-000325'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-95923r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
