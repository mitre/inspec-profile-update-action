control 'SV-253741' do
  title 'MariaDB must maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality, or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When transmitting data, MariaDB associated applications and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', "If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.
 
First, as the database administrator, verify the following settings: 
 
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_ca';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_cert';
MariaDB> SHOW GLOBAL VARIABLES LIKE 'ssl_key';
 
If SSL is not enabled, this is a finding.

If MariaDB does not employ protective measures against unauthorized disclosure and modification during preparation for transmission, this is a finding."
  desc 'fix', 'Configure the DBMS and related system components to use NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
 
Configure MariaDB to use TLS.

Details for this procedure can be found here:
https://mariadb.com/docs/security/encryption/in-transit/enable-tls-server/'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57193r841746_chk'
  tag severity: 'medium'
  tag gid: 'V-253741'
  tag rid: 'SV-253741r841748_rule'
  tag stig_id: 'MADB-10-008900'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-57144r841747_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
