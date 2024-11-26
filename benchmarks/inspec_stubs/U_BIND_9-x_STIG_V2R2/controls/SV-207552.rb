control 'SV-207552' do
  title 'The BIND 9.x server implementation must be configured to use only approved ports and protocols.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations.

To support the requirements and principles of least functionality, the application must support the organizational requirements by providing only essential capabilities and limiting the use of ports, protocols, and/or services.'
  desc 'check', 'Verify the BIND 9.x server is configured to listen on UDP/TCP port 53.

Inspect the "named.conf" file for the following:

options {
listen-on port 53 { <ip_address>; };
};

If the "port" variable is missing, this is a finding.

If the "port" variable is not set to "53", this is a finding.

Note: "<ip_address>" should be replaced with the DNS server IP address.'
  desc 'fix', 'Edit the "named.conf" file.

Add the following line to the "options" statement:

listen-on port 53 { <ip_address>; };

Replace "<ip_address>" with the IP of the name server.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7807r283710_chk'
  tag severity: 'medium'
  tag gid: 'V-207552'
  tag rid: 'SV-207552r612253_rule'
  tag stig_id: 'BIND-9X-001053'
  tag gtitle: 'SRG-APP-000142-DNS-000014'
  tag fix_id: 'F-7807r283711_fix'
  tag 'documentable'
  tag legacy: ['SV-87027', 'V-72403']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
