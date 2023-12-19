control 'SV-69107' do
  title 'The DNS server implementation must authenticate the other DNS server before responding to a server-to-server transaction.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Device authentication is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices can access the system. 

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair (TSIG) or using PKI-based authentication (SIG(0)).'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server authenticates the other DNS server before responding to a server-to-server transaction. If the DNS server does not authenticate the other DNS server, this is a finding.'
  desc 'fix', 'Configure the DNS server to authenticate the other DNS server before responding to a server-to-server transaction.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55483r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54861'
  tag rid: 'SV-69107r1_rule'
  tag stig_id: 'SRG-APP-000394-DNS-000049'
  tag gtitle: 'SRG-APP-000394-DNS-000049'
  tag fix_id: 'F-59719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
