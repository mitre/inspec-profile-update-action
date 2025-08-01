control 'SV-240075' do
  title 'HAProxy must restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.

As the web server for the vRA Virtual Appliance Management Interface (vAMI), Lighttpd is the primary remote access management system for vRA. Lighttpd must be configured to restrict inbound connections from nonsecure zones. To accomplish this, the SSL engine must be enabled. The SSL engine forces Lighttpd to only listen via secure protocols.'
  desc 'check', %q(Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to the "frontend https-in" section. 

Review the "frontend https-in" section.

Verify that the port 443 binding has the "ssl" keyword.

Verify that port 80 is binded.

Verify that non-ssl traffic is redirected to port 443.

Note: Ports are binded with this statement: 'bind 0.0.0.0:<port>', where <port> is the binded port.

Note: Non-ssl traffic is redirected with this statement: 'redirect scheme https if !{ ssl_fc }'

Note: Ensure the redirection statement appears before all 'acl' statements.

If the port 443 binding is missing the "ssl" keyword, OR port 80 is NOT binded, OR non-ssl traffic is NOT being redirected to port 443, this is a finding.)
  desc 'fix', %q(Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following three values:  

bind 0.0.0.0:80
bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3
redirect scheme https if !{ ssl_fc }

Note: Ensure the redirection statement appears before all 'acl' statements.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43308r665392_chk'
  tag severity: 'medium'
  tag gid: 'V-240075'
  tag rid: 'SV-240075r879692_rule'
  tag stig_id: 'VRAU-HA-000340'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-43267r665393_fix'
  tag 'documentable'
  tag legacy: ['SV-99837', 'V-89187']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
