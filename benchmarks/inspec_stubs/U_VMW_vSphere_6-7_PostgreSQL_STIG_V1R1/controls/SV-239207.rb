control 'SV-239207' do
  title 'VMware Postgres must use FIPS 140-2 approved TLS ciphers.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be easily broken, and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, using cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

'
  desc 'check', %q(At the command prompt, execute the following command:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SHOW ssl_ciphers;"|sed -n 3p|sed -e 's/^[ ]*//'

Expected result:

!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_ciphers TO '!aNULL:kECDH+AES:ECDH+AES:RSA+AES:@STRENGTH';"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42440r678992_chk'
  tag severity: 'high'
  tag gid: 'V-239207'
  tag rid: 'SV-239207r678994_rule'
  tag stig_id: 'VCPG-67-000015'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-42399r678993_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383']
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
