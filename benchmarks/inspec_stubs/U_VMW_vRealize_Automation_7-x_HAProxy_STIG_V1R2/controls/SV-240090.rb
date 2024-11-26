control 'SV-240090' do
  title 'HAProxy must maintain the confidentiality and integrity of information during reception.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

In order to protect the integrity and confidentiality of the remote sessions, HAProxy uses SSL/TLS.'
  desc 'check', "At the command line execute the following command:

grep -En '\\sssl\\s' /etc/haproxy/conf.d/*.cfg

If the command does not return the two lines below, this is a finding.

/etc/haproxy/conf.d/20-vcac.cfg:4:    bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3
/etc/haproxy/conf.d/30-vro-config.cfg:2:    bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3"
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/30-vro-config.cfg

Navigate to and configure the "frontend https-in-vro-config" section with the following value:  

bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3

Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following value:  

bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43323r665437_chk'
  tag severity: 'medium'
  tag gid: 'V-240090'
  tag rid: 'SV-240090r879813_rule'
  tag stig_id: 'VRAU-HA-000475'
  tag gtitle: 'SRG-APP-000442-WSR-000182'
  tag fix_id: 'F-43282r665438_fix'
  tag 'documentable'
  tag legacy: ['SV-100973', 'V-90323']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
