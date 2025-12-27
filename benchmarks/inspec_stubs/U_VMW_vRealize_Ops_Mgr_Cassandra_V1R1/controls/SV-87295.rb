control 'SV-87295' do
  title 'The Cassandra Server must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', 'Review the Cassandra Server configuration to ensure NIST FIPS 140-2 validated cryptographic modules are used for cryptographic operations.

Review the Apache2 configuration by opening the /etc/apache2/ssl-global.conf file.

Search for the <IfModule mod_ssl.c> line and ensure the SSLFIPS directive is below it.  If the SSLFIPS directive is not under the <IfModule mod_ssl.c> line, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.

To enable the FIPS mode of operation, complete the following steps:

Replace the mod_ssl.so with the following command:
  cd /usr/lib64/apache2-prefork/
  cp mod_ssl.so mod_ssl.so.old
  cp mod_ssl.so.FIPSON.openssl1.0.2 mod_ssl.so

Modify your Apache2 configuration by editing the /etc/apache2/ssl-global.conf file.

Search for the <IfModule mod_ssl.c> line and add the SSLFIPS on directive below it.

Reset the Apache configuration with the service apache2 restart command.'
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72819r1_chk'
  tag severity: 'high'
  tag gid: 'V-72663'
  tag rid: 'SV-87295r1_rule'
  tag stig_id: 'VROM-CS-002055'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-79067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
