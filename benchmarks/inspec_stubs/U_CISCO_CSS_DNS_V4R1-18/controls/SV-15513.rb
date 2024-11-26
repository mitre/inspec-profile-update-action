control 'SV-15513' do
  title 'The DNS administrator will ensure non-routeable IPv6 link-local scope addresses are not configured in any zone.  Such addresses begin with the prefixes of “FE8”, “FE9”, “FEA”, or “FEB”.'
  desc 'IPv6 link local scope addresses are not globally routable and must not be configured in any DNS zone.  Similar to RFC1918, addresses, if a link-local scope address is inserted into a zone provided to clients, most routers will not forward this traffic beyond the local subnet.'
  desc 'check', 'BIND

•	Instruction:  Examine all zone statements contained in the named.conf file for a line containing the word file designating the actual file that stores the zones records.  Examine the file that contains zones records for any IPv6 addresses containing the prefixes “FE8”, “FE9”, “FEA”, or “FEB”. If any link-local scope addresses are found, then this is a finding.


Windows DNS

•	Instruction:  From the windows task bar, select Start, Programs/All Programs, Administrative Tools, DNS to open the DNS management console.  Expand the Forward Lookup Zones folder.  Expand each zone folder and examine the host record entries.  The third column titled Data will display the IP.  Verify this column does not contain any IP address that begin with the prefixes  “FE8”, “FE9”, “FEA”, or “FEB”.'
  desc 'fix', 'The SA should remove any link-local addresses and replace with appropriate Site-Local or Global scope addresses.'
  impact 0.3
  ref 'DPMS Target Cisco CSS DNS'
  tag check_id: 'C-12979r1_chk'
  tag severity: 'low'
  tag gid: 'V-14756'
  tag rid: 'SV-15513r1_rule'
  tag stig_id: 'DNS4600'
  tag gtitle: 'IPv6 link-local scope addresses are not configured'
  tag fix_id: 'F-14234r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Other']
  tag ia_controls: 'ECSC-1'
end
