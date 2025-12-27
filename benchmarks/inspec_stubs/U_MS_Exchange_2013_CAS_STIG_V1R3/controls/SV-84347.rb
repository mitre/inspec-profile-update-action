control 'SV-84347' do
  title 'Exchange Servers must use approved DoD certificates.'
  desc "Server certificates are required for many security features in Exchange; without them the server cannot engage in many forms of secure communication. Failure to implement valid certificates makes it virtually impossible to secure Exchange's communications."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeCertificate | Select CertificateDomains, issuer

If the value of CertificateDomains does not indicate it is issued by the DoD, this is a finding.'
  desc 'fix', 'Remove the non-DoD certificate and import the correct DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69725'
  tag rid: 'SV-84347r1_rule'
  tag stig_id: 'EX13-CA-000030'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-75929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
