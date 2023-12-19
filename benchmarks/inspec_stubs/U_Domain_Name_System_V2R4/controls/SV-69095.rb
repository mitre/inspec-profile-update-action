control 'SV-69095' do
  title 'The HINFO, RP, TXT and LOC RR types must not be used in the zone SOA.'
  desc "There are several types of RRs in the DNS that are meant to convey information to humans and applications about the network, hosts, or services. These RRs include the Responsible Person (RP) record, the Host Information (HINFO) record, the Location (LOC) record, and the catch-all text string resource record (TXT) [RFC1035]. Although these record types are meant to provide information to users in good faith, they also allow attackers to gain knowledge about network hosts before attempting to exploit them. For example, an attacker may query for HINFO records, looking for hosts that list an OS or platform known to have exploits. 

Therefore, great care should be taken before including these record types in a zone. In fact, they are best left out altogether.

More careful consideration should be taken with the TXT resource record type. A DNS administrator will have to decide if the data contained in a TXT RR constitutes an information leak or is a necessary piece of information. For example, several authenticated email technologies use TXT RR's to store email sender policy information such as valid email senders for a domain. These judgments will have to be made on a case-by-case basis.

A DNS administrator should take care when including HINFO, RP, TXT, LOC, or other RR types that could divulge information that would be useful to an attacker or the external view of a zone if using split DNS. 

RRs such as HINFO and TXT provide information about software name and versions (e.g., for resources such as Web servers and mail servers) that will enable the well-equipped attacker to exploit the known vulnerabilities in those software versions and launch attacks against those resources."
  desc 'check', 'Review the DNS configuration files. Verify there are not any HINFO, RP, TXT, or LOC RR type RRs in the configuration.

If there are any HINFO, RP, TXT or LOC RR type RRs in the configuration, this is a finding.'
  desc 'fix', 'Configure the DNS configuration to not include any HINFO, RP, TXT, or LOC RR type RRs.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55471r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54849'
  tag rid: 'SV-69095r1_rule'
  tag stig_id: 'SRG-APP-000333-DNS-000107'
  tag gtitle: 'SRG-APP-000333-DNS-000107'
  tag fix_id: 'F-59707r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002201']
  tag nist: ['AC-4 (12)']
end
