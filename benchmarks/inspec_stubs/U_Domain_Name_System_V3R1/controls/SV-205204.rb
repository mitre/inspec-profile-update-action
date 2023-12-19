control 'SV-205204' do
  title 'The DNS server implementation must authenticate another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

This requirement applies to server-to-server (zone transfer) transactions only and is provided by TSIG/SIG(0), which enforces mutual server authentication using a key that is unique to each server pair (TSIG) or using PKI-based authentication (SIG(0)).'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server authenticates another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based. If the DNS server does not authenticate another DNS server before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the DNS server to authenticate another DNS server before establishing a remote and/or network connection using bidirectional authentication that is cryptographically based.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5471r392525_chk'
  tag severity: 'medium'
  tag gid: 'V-205204'
  tag rid: 'SV-205204r879768_rule'
  tag stig_id: 'SRG-APP-000395-DNS-000050'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-5471r392526_fix'
  tag 'documentable'
  tag legacy: ['SV-69109', 'V-54863']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
