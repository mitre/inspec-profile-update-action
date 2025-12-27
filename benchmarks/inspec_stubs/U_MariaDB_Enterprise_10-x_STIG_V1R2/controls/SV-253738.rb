control 'SV-253738' do
  title 'MariaDB must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of all encrypted sessions.'
  desc 'Only DoD-approved external PKIs have been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users. 

The authoritative list of DoD-approved PKIs is published at https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/unclass-ss_using_commercial_pki_certificates.pdf.

This requirement focuses on communications protection for the MariaDB session rather than for the network packet.'
  desc 'check', "As the database administrator, check the following variables: 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_ca';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_cert'; 

The Value column will show the fully qualified file name of the ssl_ca and ssl_cert respectively. The issuer can be found by running the following command:
$ openssl x509 -in  fully-qualified-file-name-of-ssl_ca  -noout -issuer
$ openssl x509 -in  fully-qualified-file-name-of-ssl_cert  -noout -issuer
 
The issuer should be checked against the authoritative list of DoD-approved PKIs, which is published at https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/unclass-ss_using_commercial_pki_certificates.pdf.

If the DBMS will accept non-DoD approved PKI end-entity certificates, this is a finding."
  desc 'fix', 'Revoke trust in any certificates not issued by a DoD-approved certificate authority.   
 
Configure MariaDB to accept only DoD and DoD-approved PKI end-entity certificates.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57190r841737_chk'
  tag severity: 'medium'
  tag gid: 'V-253738'
  tag rid: 'SV-253738r841739_rule'
  tag stig_id: 'MADB-10-008500'
  tag gtitle: 'SRG-APP-000427-DB-000385'
  tag fix_id: 'F-57141r841738_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
