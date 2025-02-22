control 'SV-207268' do
  title 'Exchange Servers must use approved DoD certificates.'
  desc "Server certificates are required for many security features in Exchange; without them, the server cannot engage in many forms of secure communication. 

Failure to implement valid certificates makes it virtually impossible to secure Exchange's communications."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeCertificate | Select CertificateDomains, issuer

If the value of CertificateDomains does not indicate it is issued by the DoD, this is a finding.'
  desc 'fix', 'Remove the non-DoD certificate and import the correct DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7526r393317_chk'
  tag severity: 'medium'
  tag gid: 'V-207268'
  tag rid: 'SV-207268r615936_rule'
  tag stig_id: 'EX13-MB-000010'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-7526r393318_fix'
  tag 'documentable'
  tag legacy: ['SV-84565', 'V-69943']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
