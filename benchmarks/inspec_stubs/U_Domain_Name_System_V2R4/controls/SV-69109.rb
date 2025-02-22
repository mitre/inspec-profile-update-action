control 'SV-69109' do
  title 'The DNS server implementation must authenticate another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair (TSIG) or using PKI-based authentication (SIG(0)).'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server authenticates another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based. If the DNS server does not authenticate another DNS server before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the DNS server to authenticate another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55485r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54863'
  tag rid: 'SV-69109r1_rule'
  tag stig_id: 'SRG-APP-000395-DNS-000050'
  tag gtitle: 'SRG-APP-000395-DNS-000050'
  tag fix_id: 'F-59721r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
