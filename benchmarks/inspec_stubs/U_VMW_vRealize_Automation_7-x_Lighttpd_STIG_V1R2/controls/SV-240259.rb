control 'SV-240259' do
  title 'Lighttpd must restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.

As the web server for the vRA Virtual Appliance Management Interface (vAMI), Lighttpd is the primary remote access management system for vRA. Lighttpd must be configured to restrict inbound connections from nonsecure zones. To accomplish this, the SSL engine must be enabled. The SSL engine forces Lighttpd to only listen via secure protocols.'
  desc 'check', %q(At the command prompt, execute the following command:    

grep -A 4 'remoteip' /opt/vmware/etc/lighttpd/lighttpd.conf

If the command does not return any output, this is a finding.

Note: The output should look like the following: 

$HTTP["remoteip"] !~ "a.a.a.a" {
    url.access-deny = ( "" )
 }
Where a.a.a.a is an allowed IP address.)
  desc 'fix', 'Determine the IP addresses which will be allowed to access Lighttpd.

Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following: 

$HTTP["remoteip"] !~ "a.a.a.a" {
    url.access-deny = ( "" )
 }

Note: a.a.a.a is the IPv4 address provided by the ISSO. If additional IPv4 addresses are allowed, use the information shown below instead (3 addresses shown):

$HTTP["remoteip"] !~ "a.a.a.a|b.b.b.b|c.c.c.c" {
    url.access-deny = ( "" )
 }'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43492r854815_chk'
  tag severity: 'medium'
  tag gid: 'V-240259'
  tag rid: 'SV-240259r879692_rule'
  tag stig_id: 'VRAU-LI-000375'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-43451r854816_fix'
  tag 'documentable'
  tag legacy: ['SV-100985', 'V-90335']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
