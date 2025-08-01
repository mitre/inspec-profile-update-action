control 'SV-70215' do
  title 'The web server must restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.'
  desc 'check', 'Review the web server configuration to verify that the web server is restricting access from nonsecure zones.

If the web server is not configured to restrict access from nonsecure zones, then this is a finding.'
  desc 'fix', 'Configure the web server to block access from DoD-defined nonsecure zones.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56531r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55961'
  tag rid: 'SV-70215r2_rule'
  tag stig_id: 'SRG-APP-000315-WSR-000004'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-60839r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
