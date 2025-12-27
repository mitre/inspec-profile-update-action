control 'SV-44046' do
  title 'Servers must use approved DoD certificates.'
  desc "Server certificates are required for many security features in Exchange; without them the server cannot engage in many forms of secure communication. 
Failure to implement valid certificates makes it virtually impossible to secure Exchange's communications."
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ExchangeCertificate | Select CertificateDomains, issuer

If the value of 'CertificateDomains' does not indicate it is issued by the DoD, this is a finding."
  desc 'fix', 'Remove the non-DoD certificate and import the correct DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41733r5_chk'
  tag severity: 'medium'
  tag gid: 'V-33626'
  tag rid: 'SV-44046r2_rule'
  tag stig_id: 'Exch-2-014'
  tag gtitle: 'Exch-2-014'
  tag fix_id: 'F-37518r1_fix'
  tag 'documentable'
end
