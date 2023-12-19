control 'SV-206603' do
  title 'The DBMS must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate.  PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.

This requirement focuses on communications protection for the DBMS session rather than for the network packet.'
  desc 'check', 'If the DBMS will accept non-DoD approved PKI end-entity certificates, this is a finding.'
  desc 'fix', 'Revoke trust in any certificates not issued by a DoD-approved certificate authority.   Configure the DBMS to accept only DoD and DoD-approved PKI end-entity certificates.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6863r291477_chk'
  tag severity: 'medium'
  tag gid: 'V-206603'
  tag rid: 'SV-206603r617447_rule'
  tag stig_id: 'SRG-APP-000427-DB-000385'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-6863r291478_fix'
  tag 'documentable'
  tag legacy: ['SV-72597', 'V-58167']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
