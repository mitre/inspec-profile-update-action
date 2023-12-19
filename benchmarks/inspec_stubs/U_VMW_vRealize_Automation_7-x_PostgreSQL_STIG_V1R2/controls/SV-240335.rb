control 'SV-240335' do
  title 'The vRA PostgreSQL database must use FIPS 140-2 ciphers.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*ssl_ciphers\b' /storage/db/pgdata/postgresql.conf

If "ssl_ciphers" is not "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl_ciphers TO 'FIPS: +3DES:!aNULL';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43568r668847_chk'
  tag severity: 'high'
  tag gid: 'V-240335'
  tag rid: 'SV-240335r879885_rule'
  tag stig_id: 'VRAU-PG-000475'
  tag gtitle: 'SRG-APP-000514-DB-000382'
  tag fix_id: 'F-43527r668848_fix'
  tag 'documentable'
  tag legacy: ['SV-100097', 'V-89447']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
