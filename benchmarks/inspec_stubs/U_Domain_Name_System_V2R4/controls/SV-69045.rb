control 'SV-69045' do
  title 'The DNS server implementation must uniquely identify the other DNS server before responding to a server-to-server transaction.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. This applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair (TSIG) or using PKI-based authentication (SIG(0)), thus uniquely identifying the other server.'
  desc 'check', "Review the DNS server implementation configuration to determine if it validates other DNS servers' unique identify, through the use TSIG or SIG(0), when accepting server-to-server (zone transfer) transactions from the other DNS servers.

If the DNS server does not validate other DNS servers' unique identity, through the use of either TSIG or SIG(0), when accepting server-to-server (zone transfer) transactions from those other DNS servers, this is a finding."
  desc 'fix', "Configure the DNS server to verify another DNS server's unique identify, through the use of TSIG or SIG(0), when accepting server-to-server (zone transfer) transactions from other DNS servers."
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55421r3_chk'
  tag severity: 'medium'
  tag gid: 'V-54799'
  tag rid: 'SV-69045r1_rule'
  tag stig_id: 'SRG-APP-000158-DNS-000015'
  tag gtitle: 'SRG-APP-000158-DNS-000015'
  tag fix_id: 'F-59657r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
