control 'SV-100971' do
  title 'HAProxy session IDs must be sent to the client using SSL/TLS.'
  desc 'The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data that is used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.

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
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-90015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90321'
  tag rid: 'SV-100971r1_rule'
  tag stig_id: 'VRAU-HA-000440'
  tag gtitle: 'SRG-APP-000439-WSR-000152'
  tag fix_id: 'F-97063r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
