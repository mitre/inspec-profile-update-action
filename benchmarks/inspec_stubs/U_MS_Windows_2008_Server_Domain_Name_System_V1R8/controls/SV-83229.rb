control 'SV-83229' do
  title 'The HINFO, RP, TXT, and LOC RR types must not be used in the zone SOA.'
  desc "There are several types of RRs in the DNS that are meant to convey information to humans and applications about the network, hosts, or services. These RRs include the Responsible Person (RP) record, the Host Information (HINFO) record, the Location (LOC) record, and the catch-all text string resource record (TXT) [RFC1035]. Although these record types are meant to provide information to users in good faith, they also allow attackers to gain knowledge about network hosts before attempting to exploit them. For example, an attacker may query for HINFO records, looking for hosts that list an OS or platform known to have exploits.

Therefore, great care should be taken before including these record types in a zone. In fact, they are best left out altogether.

More careful consideration should be taken with the TXT resource record type. A DNS administrator will have to decide if the data contained in a TXT RR constitutes an information leak or is a necessary piece of information. For example, several authenticated email technologies use TXT RR's to store email sender policy information such as valid email senders for a domain. These judgments will have to be made on a case-by-case basis.

A DNS administrator should take care when including HINFO, RP, TXT, LOC, or other RR types that could divulge information that would be useful to an attacker or the external view of a zone if using split DNS.

RRs such as HINFO and TXT provide information about software name and versions (e.g., for resources such as Web servers and mail servers) that will enable the well-equipped attacker to exploit the known vulnerabilities in those software versions and launch attacks against those resources."
  desc 'check', "Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Review the zone's Resource Records (RR) and verify HINFO, RP, and LOC RRs are not used. If TXT RRs are used, they must not reveal any information about the organization which could be used for malicious purposes.

If there are any HINFO, RP, LOC, or revealing TXT RRs in any zone hosted by the DNS Server, this is a finding."
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Remove all HINFO, RP, TXT, and LOC RRs from all zones hosted by the DNS Server.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59611r6_chk'
  tag severity: 'medium'
  tag gid: 'V-58739'
  tag rid: 'SV-83229r1_rule'
  tag stig_id: 'WDNS-SI-000004'
  tag gtitle: 'SRG-APP-000333-DNS-000107'
  tag fix_id: 'F-64123r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
