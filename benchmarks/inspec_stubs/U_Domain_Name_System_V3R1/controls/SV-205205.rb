control 'SV-205205' do
  title 'The DNS server implementation, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates). 

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. So, in cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server, for PKI-based authentication (i.e., SIG(0)), implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network. If the DNS server does not implement such a cache of revocation data, this is a finding.'
  desc 'fix', 'Configure the DNS server, for PKI-based authentication, to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5472r392528_chk'
  tag severity: 'medium'
  tag gid: 'V-205205'
  tag rid: 'SV-205205r879774_rule'
  tag stig_id: 'SRG-APP-000401-DNS-000051'
  tag gtitle: 'SRG-APP-000401'
  tag fix_id: 'F-5472r392529_fix'
  tag 'documentable'
  tag legacy: ['SV-69111', 'V-54865']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
