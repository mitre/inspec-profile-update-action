control 'SV-253737' do
  title "MariaDB must use NSA-approved cryptography to protect classified information in accordance with the data owner's requirements."
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NSA-approved cryptography for classified networks is hardware based. This requirement addresses the compatibility of MariaDB with the encryption devices.'
  desc 'check', "If MariaDB is deployed in an unclassified environment, this is not applicable (NA).

If MariaDB is not using NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, this is a finding.

To check if MariaDB is configured to use SSL, as the database administrator: 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'have_ssl';

If have_ssl is not YES, this is a finding.

Consult network administration staff to determine whether the server is protected by NSA-approved encrypting devices. If not, this a finding."
  desc 'fix', 'Configure the DBMS and related system components to use NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
 
Configure MariaDB to use TLS.

Details for this procedure can be found here:
https://mariadb.com/docs/security/encryption/in-transit/enable-tls-server/'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57189r841734_chk'
  tag severity: 'high'
  tag gid: 'V-253737'
  tag rid: 'SV-253737r841736_rule'
  tag stig_id: 'MADB-10-008400'
  tag gtitle: 'SRG-APP-000416-DB-000380'
  tag fix_id: 'F-57140r841735_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
