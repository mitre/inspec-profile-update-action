control 'SV-99853' do
  title 'HAProxy vro frontend must be bound to the correct port 8283.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The HAProxy load balancer in the vRA appliance listens to ports 8283 on behalf of the vro configuration service.'
  desc 'check', %q(At the command prompt, execute the following command:
 
grep 'bind' /etc/haproxy/conf.d/30-vro-config.cfg
 
If the value for bind is not set to "8283", this is a finding.)
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/30-vro-config.cfg

Navigate to and configure the "frontend https-in-vro-config" section with the following value:  

bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89203'
  tag rid: 'SV-99853r1_rule'
  tag stig_id: 'VRAU-HA-000405'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-95945r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
