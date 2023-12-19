control 'SV-99867' do
  title 'HAProxy must set the maxconn value.'
  desc 'Limiting the total number of connections that a server is allowed to open prevents an attacker from overloading a web server. Overloading the server will prevent it from managing other tasks besides serving web requests.

This setting works together with per-client limits to mitigate against DDoS attacks.'
  desc 'check', 'At the command line execute the following command:
 
grep maxconn /etc/haproxy/haproxy.cfg
 
If the "maxconn" value is not set to "32768", this is a finding.'
  desc 'fix', 'Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to the "globals" section and add the following line:

maxconn 32768'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89217'
  tag rid: 'SV-99867r1_rule'
  tag stig_id: 'VRAU-HA-000490'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-95959r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
