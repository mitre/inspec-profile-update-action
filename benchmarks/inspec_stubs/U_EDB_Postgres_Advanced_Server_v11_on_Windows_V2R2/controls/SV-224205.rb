control 'SV-224205' do
  title 'The EDB Postgres Advanced Server must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs evaluated to ensure security controls and identity vetting procedures are in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at https://cyber.mil/pki-pke/interoperability/.

This requirement focuses on communications protection for the DBMS session rather than for the network packet.'
  desc 'check', 'In a Windows CMD prompt, run this command:

CertUtil <postgresql data directory>\\server.crt

If the "Issuer" that is printed out is not a DoD entity, this is a finding.'
  desc 'fix', 'Contact your program security office to request DoD issued certificates:

root.crt (CA Certificate)
server.crt
server.key'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25878r495633_chk'
  tag severity: 'medium'
  tag gid: 'V-224205'
  tag rid: 'SV-224205r508023_rule'
  tag stig_id: 'EP11-00-009100'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-25866r495634_fix'
  tag 'documentable'
  tag legacy: ['SV-109535', 'V-100431']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
