control 'SV-215596' do
  title 'AAAA addresses must not be configured in a zone for hosts that are not IPv6-aware.'
  desc 'DNS is only responsible for resolving a domain name to an IP address.  Applications and operating systems are responsible for processing the IPv6 or IPv4 record that may be returned.  With this in mind, a denial of service could easily be implemented for an application that is not IPv6-aware.  When the application receives an IP address in hexadecimal, it is up to the application/operating system to decide how to handle the response.  Combining both IPv6 and IPv4 records into the same domain can lead to application problems that are beyond the scope of the DNS administrator.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, select each zone and examine the host record entries. The third column titled “Data” will display the IP.

Verify if any contain both IPv4 and IPv6 addresses.

If any hostnames contain both IPv4 and IPv6 addresses, confirm with the SA that the actual hosts are IPv6-aware.

If any zone contains hosts with both IPv4 and IPv6 addresses but are determined to be non-IPv6-aware, this is a finding.'
  desc 'fix', 'Remove any IPv6 records for hosts which are not IPv6-aware.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16790r572233_chk'
  tag severity: 'medium'
  tag gid: 'V-215596'
  tag rid: 'SV-215596r561297_rule'
  tag stig_id: 'WDNS-CM-000027'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-16788r572234_fix'
  tag 'documentable'
  tag legacy: ['SV-73055', 'V-58625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
