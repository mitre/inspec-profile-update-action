control 'SV-228355' do
  title 'Exchange servers must use approved DoD certificates.'
  desc "Server certificates are required for many security features in Exchange; without them, the server cannot engage in many forms of secure communication.

Failure to implement valid certificates makes it virtually impossible to secure Exchange's communications."
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeCertificate | Select CertificateDomains, issuer

If the value of "CertificateDomains" does not indicate it is issued by the DoD, this is a finding.'
  desc 'fix', 'Remove the non-DoD certificate and import the correct DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30588r496861_chk'
  tag severity: 'medium'
  tag gid: 'V-228355'
  tag rid: 'SV-228355r879530_rule'
  tag stig_id: 'EX16-MB-000020'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-30573r496862_fix'
  tag 'documentable'
  tag legacy: ['SV-95335', 'V-80625']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
