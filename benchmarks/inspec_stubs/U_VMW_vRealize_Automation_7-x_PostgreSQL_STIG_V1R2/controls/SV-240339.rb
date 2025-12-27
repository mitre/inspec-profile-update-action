control 'SV-240339' do
  title 'The DBMS must use NIST FIPS 140-2 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*ssl_ciphers\b' /storage/db/pgdata/postgresql.conf

If "ssl_ciphers" is not "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_ciphers TO 'FIPS: +3DES:!aNULL';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43572r668859_chk'
  tag severity: 'high'
  tag gid: 'V-240339'
  tag rid: 'SV-240339r879616_rule'
  tag stig_id: 'VRAU-PG-000505'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-43531r668860_fix'
  tag 'documentable'
  tag legacy: ['SV-100105', 'V-89455']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
