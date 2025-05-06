control 'SV-240089' do
  title 'HAProxy must remove all export ciphers.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference. The web server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
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
  tag check_id: 'C-43322r665434_chk'
  tag severity: 'medium'
  tag gid: 'V-240089'
  tag rid: 'SV-240089r879810_rule'
  tag stig_id: 'VRAU-HA-000465'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-43281r665435_fix'
  tag 'documentable'
  tag legacy: ['SV-99863', 'V-89213']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
