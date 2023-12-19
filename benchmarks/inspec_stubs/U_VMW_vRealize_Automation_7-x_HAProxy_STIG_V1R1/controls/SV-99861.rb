control 'SV-99861' do
  title 'HAProxy must set the no-sslv3 value on all client ports.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.'
  desc 'check', "At the command prompt, execute the following command:

grep -EnR '\\bbind\\b.*\\bssl\\b' /etc/haproxy

Verify that each returned line contains the no-sslv3 value.

If any lines do not have this value, this is a finding."
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/30-vro-config.cfg

Navigate to and configure the "frontend https-in-vro-config" section with the following value:  

bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3

Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following value:  

bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88903r1_chk'
  tag severity: 'high'
  tag gid: 'V-89211'
  tag rid: 'SV-99861r1_rule'
  tag stig_id: 'VRAU-HA-000460'
  tag gtitle: 'SRG-APP-000439-WSR-000156'
  tag fix_id: 'F-95953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
