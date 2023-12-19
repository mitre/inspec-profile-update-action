control 'SV-205196' do
  title 'The DNS server implementation must strongly bind the identity of the DNS server with the DNS information.'
  desc 'Weakly bound credentials can be modified without invalidating the credential; therefore, non-repudiation can be violated.

This requirement supports audit requirements that provide organizational personnel with the means to identify who produced specific information in the event of an information transfer. Organizations and/or data owners determine and approve the strength of the binding between the information producer and the information based on the security category of the information and relevant risk factors.

DNSSEC and TSIG/SIG(0) both use digital signatures to establish the identity of the producer of particular pieces of information.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server strongly binds the identity of the DNS server with the DNS information. Examples include enabling DNSSEC and enabling TSIG or SIG(0). If the DNS server does not strongly bind the identity of the DNS server with the DNS information, this is a finding.'
  desc 'fix', 'Configure the DNS server to strongly bind the identity of the DNS server with the DNS information.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5463r392501_chk'
  tag severity: 'medium'
  tag gid: 'V-205196'
  tag rid: 'SV-205196r879724_rule'
  tag stig_id: 'SRG-APP-000347-DNS-000041'
  tag gtitle: 'SRG-APP-000347'
  tag fix_id: 'F-5463r392502_fix'
  tag 'documentable'
  tag legacy: ['SV-69217', 'V-54971']
  tag cci: ['CCI-001901', 'CCI-000366']
  tag nist: ['AU-10 (1) (a)', 'CM-6 b']
end
