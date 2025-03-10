control 'SV-15514' do
  title 'AAAA addresses are configured  on a host that is not IPv6 aware.'
  desc 'DNS is only responsible for resolving a domain name to an ip address.  Applications and operating systems are responsible for processing the IPv6 or IPv4 record that may be returned.  With this in mind, a denial of service could easily be implemented for an application that is not IPv6 aware.  When the application receives an i.p. address in hexadecimal, it is up to the application/operating system to decide how to handle the response.  Combining both IPv6 and IPv4 records into the same domain can lead to application problems that are beyond the scope of the DNS administrator.'
  desc 'check', 'BIND

•	Instruction:  Examine all zone statements contained in the named.conf file for a line containing the word file designating the actual file that stores the zones records.  Examine the file that contains zones records and verify IPv6 and IPv4 resource records are not in the same file.  If the records are found in the same file, then this is a finding.


Windows DNS

Instruction:  From the Windows task bar, select Start, Programs/All Programs, Administrative Tools, DNS to open the DNS management console.  Expand the Forward Lookup Zones folder.  Expand each zone folder and examine the host record entries.  The third column titled Data will display the IP.  Verify this column does not contain both IPv4 and IPv6 addresses.'
  desc 'fix', 'The SA should remove the IPv6 records from the IPv4 zone and create a second zone with all IPv6 records.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-12980r1_chk'
  tag severity: 'low'
  tag gid: 'V-14757'
  tag rid: 'SV-15514r1_rule'
  tag stig_id: 'DNS4610'
  tag gtitle: 'AAAA addresses are on host that is not IPv6 aware'
  tag fix_id: 'F-14235r1_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'ECSC-1'
end
