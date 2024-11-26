control 'SV-215585' do
  title 'For zones split between the external and internal sides of a network, the RRs for the external hosts must be separate from the RRs for the internal hosts.'
  desc 'Authoritative name servers for an enterprise may be configured to receive requests from both external and internal clients. 

External clients need to receive RRs that pertain only to public services (public Web server, mail server, etc.) 

Internal clients need to receive RRs pertaining to public services as well as internal hosts. 

The zone information that serves the RRs on both the inside and the outside of a firewall should be split into different physical files for these two types of clients (one file for external clients and one file for internal clients).'
  desc 'check', "Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

For each zone, review the records.

If any RRs (Resource Records) on an internal DNS server resolve to IP addresses located outside the internal DNS server's network, this is a finding.

If any RRs (Resource Records) on an external DNS server resolve to IP addresses located inside the network, this is a finding."
  desc 'fix', 'Remove any RRs from the internal zones for which the resolution is for an external IP address.

Remove any RRs from the external zones for which the resolution is for an internal IP address.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16779r572215_chk'
  tag severity: 'medium'
  tag gid: 'V-215585'
  tag rid: 'SV-215585r561297_rule'
  tag stig_id: 'WDNS-CM-000016'
  tag gtitle: 'SRG-APP-000516-DNS-000091'
  tag fix_id: 'F-16777r572216_fix'
  tag 'documentable'
  tag legacy: ['SV-73033', 'V-58603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
