control 'SV-83295' do
  title 'AAAA addresses must not be configured in a zone for hosts that are not IPv6-aware.'
  desc 'DNS is only responsible for resolving a domain name to an IP address.  Applications and operating systems are responsible for processing the IPv6 or IPv4 record that may be returned.  With this in mind, a denial of service could easily be implemented for an application that is not IPv6-aware.  When the application receives an IP address in hexadecimal, it is up to the application/operating system to decide how to handle the response.  Combining both IPv6 and IPv4 records into the same domain can lead to application problems that are beyond the scope of the DNS administrator.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, select each zone and examine the host record entries. The third column titled “Data” will display the IP.

Verify if any contain both IPv4 and IPv6 addresses.

If any hostnames contain both IPv4 and IPv6 addresses, confirm with the SA that the actual hosts are IPv6-aware.

If any zone contains hosts with both IPv4 and IPv6 addresses but are determined to be non-IPv6-aware, this is a finding.'
  desc 'fix', 'Remove any IPv6 records for hosts which are not IPv6-aware.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59497r2_chk'
  tag severity: 'medium'
  tag gid: 'V-58625'
  tag rid: 'SV-83295r1_rule'
  tag stig_id: 'WDNS-CM-000027'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-64009r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
