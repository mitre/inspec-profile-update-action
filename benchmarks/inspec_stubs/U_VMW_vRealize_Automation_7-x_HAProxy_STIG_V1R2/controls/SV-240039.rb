control 'SV-240039' do
  title 'HAProxy must limit the amount of time that an http request can be received.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Mitigating this kind of attack will include limiting the parameter values associated with keepalive, (i.e., a parameter used to limit the amount of time a connection may be inactive).

HAProxy provides an http-request timeout parameter that set the maximum allowed time to wait for a complete HTTP request. Setting this parameter will mitigate slowloris DoS attacks. Slowloris tries to keep many connections to the target web server open and hold them open as long as possible. It accomplishes this by opening connections to the target web server and sending a partial request. Periodically, it will send subsequent HTTP headers, adding to—but never completing—the request.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'timeout http-request' /etc/haproxy/haproxy.cfg

If the value of ''timeout http-request" is not set to "5000", is commented out, or is missing, this is a finding.)
  desc 'fix', "Navigate to and open /etc/haproxy/haproxy.cfg   

Configure the haproxy.cfg file with the following value in the global section: 

'timeout http-request 5000'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43272r665284_chk'
  tag severity: 'medium'
  tag gid: 'V-240039'
  tag rid: 'SV-240039r879511_rule'
  tag stig_id: 'VRAU-HA-000005'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43231r665285_fix'
  tag 'documentable'
  tag legacy: ['SV-100947', 'V-90297']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
