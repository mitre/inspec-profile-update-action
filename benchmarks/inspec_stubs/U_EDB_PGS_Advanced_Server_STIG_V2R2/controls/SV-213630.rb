control 'SV-213630' do
  title 'The EDB Postgres Advanced Server must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability.

This requirement focuses on communications protection for the DBMS session rather than for the network packet.'
  desc 'check', 'Verify that the root.crt certificate was issued by a valid DoD entity.

> openssl x509 -in <postgresql data directory>/root.crt –text | grep –i “issuer”.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

If any issuers are listed that are not valid DoD certificate authorities, this is a finding.'
  desc 'fix', "Remove any certificate that was not issued by a valid DoD certificate authority.

Contact the organization's certificate issuer and request a new certificate that is issued by a valid DoD certificate authorities."
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14852r290202_chk'
  tag severity: 'medium'
  tag gid: 'V-213630'
  tag rid: 'SV-213630r508024_rule'
  tag stig_id: 'PPS9-00-009100'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-14850r290203_fix'
  tag 'documentable'
  tag legacy: ['SV-83617', 'V-69013']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
