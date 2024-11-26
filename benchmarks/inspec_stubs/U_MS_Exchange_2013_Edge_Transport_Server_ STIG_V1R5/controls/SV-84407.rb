control 'SV-84407' do
  title 'Exchange servers must use approved DoD certificates.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeCertificate | Select CertificateDomains, issuer

If the value of CertificateDomains does not indicate it is issued by the DoD, this is a finding.'
  desc 'fix', 'Remove the non-DoD certificate and import the correct DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70237r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69785'
  tag rid: 'SV-84407r1_rule'
  tag stig_id: 'EX13-EG-000010'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-75997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
