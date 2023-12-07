control 'SV-214343' do
  title 'The Apache web server must restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the Apache web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through the internal Apache web server access list, the Apache web server can stop or slow denial-of-service (DoS) attacks on the Apache web server.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "IP Address Restrictions" are not configured or IP ranges configured to be "Allow" are not restrictive enough to prevent connections from nonsecure zones, this is a finding.)
  desc 'fix', 'Configure the "http.conf" file to include restrictions.

Example: 

<RequireAll>
Require not host phishers.example.com moreidiots.example
</RequireAll>

Restart the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15555r277532_chk'
  tag severity: 'medium'
  tag gid: 'V-214343'
  tag rid: 'SV-214343r879692_rule'
  tag stig_id: 'AS24-W1-000670'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-15553r277533_fix'
  tag 'documentable'
  tag legacy: ['SV-102527', 'V-92439']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
