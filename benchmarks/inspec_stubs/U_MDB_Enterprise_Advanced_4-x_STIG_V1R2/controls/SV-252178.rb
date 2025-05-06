control 'SV-252178' do
  title 'MongoDB must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at https://cyber.mil/pki-pke/.

This requirement focuses on communications protection for MongoDB session rather than for the network packet.'
  desc 'check', 'To run MongoDB in TLS mode, obtain a valid certificate singed by a single certificate authority. 

Before starting the MongoDB database in TLS mode, verify that certificate used is issued by a valid DoD certificate authority (openssl x509 -in path_to_certificate_pem_file -text | grep -i issuer).

If there is any issuer present in the certificate that is not a DoD approved certificate authority, this is a finding.'
  desc 'fix', "Remove any certificate that was not issued by an approved DoD certificate authority. Contact the organization's certificate issuer and request a new certificate that is issued by a valid DoD certificate authority."
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55634r813914_chk'
  tag severity: 'medium'
  tag gid: 'V-252178'
  tag rid: 'SV-252178r855519_rule'
  tag stig_id: 'MD4X-00-005800'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-55584r817014_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
