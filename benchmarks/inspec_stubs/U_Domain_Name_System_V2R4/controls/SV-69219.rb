control 'SV-69219' do
  title 'The DNS server implementation must provide the means for authorized individuals to determine the identity of the source of the DNS server-provided information.'
  desc 'Without a means for identifying the individual that produced the information, the information cannot be relied upon. Identifying the validity of information may be delayed or deterred.

This requirement provides organizational personnel with the means to identify who produced specific information in the event of an information transfer. DNSSEC and TSIG/SIG(0) both use digital signatures to establish the identity of the producer of particular pieces of information. These signatures can be examined and verified to determine the identity of the producer of the information.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server provides the means for authorized individuals to determine the identity of the source of the DNS server-provided information. If the DNS server does not provide such means, this is a finding.'
  desc 'fix', 'Configure the DNS server to provide the means for authorized individuals to determine the identity of the source of the DNS server-provided information.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54973'
  tag rid: 'SV-69219r1_rule'
  tag stig_id: 'SRG-APP-000348-DNS-000042'
  tag gtitle: 'SRG-APP-000348-DNS-000042'
  tag fix_id: 'F-59835r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001902']
  tag nist: ['CM-6 b', 'AU-10 (1) (b)']
end
