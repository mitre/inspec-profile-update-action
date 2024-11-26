control 'SV-98919' do
  title 'The vROps PostgreSQL DB must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*ssl_ciphers\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If ssl_ciphers is not set to "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# sed -i.bak "/ssl_ciphers\s.*/ d" /storage/db/vcops/vpostgres/data/postgresql.conf
# sed -i "$ a ssl_ciphers = 'FIPS: +3DES:\!aNULL'" /storage/db/vcops/vpostgres/data/postgresql.conf
# su postgres
postgres@vRealizeClusterNode:> cd /opt/vmware/vpostgres/current
postgres@vRealizeClusterNode:> /opt/vmware/vpostgres/9.3/bin/pg_ctl restart -D /storage/db/vcops/vpostgres/data
postgres@vRealizeClusterNode:> exit)
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87961r1_chk'
  tag severity: 'high'
  tag gid: 'V-88269'
  tag rid: 'SV-98919r1_rule'
  tag stig_id: 'VROM-PG-000220'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-95011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
