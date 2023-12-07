control 'SV-214388' do
  title 'The Apache web server must restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through the internal web server access list, the web server can stop or slow denial-of-service (DoS) attacks on the web server.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If "IP Address Restrictions" are not configured or IP ranges configured to be "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.)
  desc 'fix', 'Configure the "http.conf" file to include restrictions.

Example: 

<RequireAll>
Require not host phishers.example.com moreidiots.example
</RequireAll>'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15599r277905_chk'
  tag severity: 'medium'
  tag gid: 'V-214388'
  tag rid: 'SV-214388r399640_rule'
  tag stig_id: 'AS24-W2-000670'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-15597r277906_fix'
  tag 'documentable'
  tag legacy: ['SV-102653', 'V-92565']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
