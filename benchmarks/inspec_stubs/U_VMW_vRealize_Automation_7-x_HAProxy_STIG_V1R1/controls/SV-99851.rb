control 'SV-99851' do
  title 'HAProxy vcac frontend must be bound to ports 80 and 443.'
  desc 'Web servers provide numerous processes, features, and functionalities that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The HAProxy load balancer in the vRA appliance listens to ports 80 and 443 on behalf of the vcac service.'
  desc 'check', %q(At the command prompt, execute the following command:
 
grep 'bind' /etc/haproxy/conf.d/20-vcac.cfg
 
If two lines are not returned, this is a finding. 

If the values for bind are not set to "80" and to "443", this is a finding.)
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following two values:  

bind 0.0.0.0:80
bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89201'
  tag rid: 'SV-99851r1_rule'
  tag stig_id: 'VRAU-HA-000400'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-95943r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
