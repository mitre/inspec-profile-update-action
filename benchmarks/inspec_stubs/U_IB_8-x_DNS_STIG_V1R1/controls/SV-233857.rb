control 'SV-233857' do
  title 'The Infoblox DNS server must not reveal sensitive information to an attacker. This includes HINFO, RP, LOC resource, and sensitive TXT record data.'
  desc 'There are several types of resource records (RRs) in the DNS that are meant to convey information to humans and applications about the network, hosts, or services. These include the Responsible Person (RP) record, the Host Information (HINFO) record, the Location (LOC) record, and the catch-all text string resource record (TXT) [RFC1035]. 

Although these record types are meant to provide information to users in good faith, they also allow attackers to gain knowledge about network hosts before attempting to exploit them. For example, an attacker may query for HINFO records, looking for hosts that list an operating system or platform known to have exploits. 

Therefore, great care should be taken before including these record types in a zone. In fact, they are best left out altogether.

More careful consideration should be taken with the TXT resource record type. A DNS administrator will have to decide if the data contained in a TXT RR constitutes an information leak or is a necessary piece of information. For example, several authenticated email technologies use TXT RRs to store email sender policy information, such as valid email senders for a domain. These judgments will have to be made on a case-by-case basis.

A DNS administrator should take care when including HINFO, RP, TXT, LOC, or other RR types that could divulge information that would be useful to an attacker or the external view of a zone if using split DNS. 

RRs such as HINFO and TXT provide information about software name and versions (e.g., for resources such as web servers and mail servers) that will enable the well-equipped attacker to exploit the known vulnerabilities in those software versions and launch attacks against those resources.'
  desc 'check', 'Review external DNS zone data and verify there are no HINFO, LOC, RP, or TXT RRs that disclose any information that may be used for malicious purposes.  

1. Navigate to Data Management >> DNS >> Zones tab.  
2. Click on the appropriate DNS Zone. 
3. Review external zone data for HINFO, LOC, RP, and TXT RRs.  

If any HINFO, LOC, RP, or TXT RRs exist that disclose any information that may be used for malicious purposes, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Zones. 
2. Select and edit the zone identified during the Check.
3. Select the RR and click "Delete" to remove the record.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37042r611091_chk'
  tag severity: 'medium'
  tag gid: 'V-233857'
  tag rid: 'SV-233857r621666_rule'
  tag stig_id: 'IDNS-8X-200001'
  tag gtitle: 'SRG-APP-000333-DNS-000107'
  tag fix_id: 'F-37007r611092_fix'
  tag 'documentable'
  tag cci: ['CCI-002201']
  tag nist: ['AC-4 (12)']
end
