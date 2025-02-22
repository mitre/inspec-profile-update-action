control 'SV-239835' do
  title 'The vROps PostgreSQL DB must implement NIST FIPS 140-2 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*ssl_ciphers\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If "ssl_ciphers" is not set to "FIPS: +3DES:!aNULL", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# sed -i.bak "/ssl_ciphers\s.*/ d" /storage/db/vcops/vpostgres/data/postgresql.conf
# sed -i "$ a ssl_ciphers = 'FIPS: +3DES:\!aNULL'" /storage/db/vcops/vpostgres/data/postgresql.conf
# su postgres
postgres@vRealizeClusterNode:> cd /opt/vmware/vpostgres/current
postgres@vRealizeClusterNode:> /opt/vmware/vpostgres/9.3/bin/pg_ctl restart -D /storage/db/vcops/vpostgres/data
postgres@vRealizeClusterNode:> exit)
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43068r663880_chk'
  tag severity: 'high'
  tag gid: 'V-239835'
  tag rid: 'SV-239835r879885_rule'
  tag stig_id: 'VROM-PG-000605'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-43027r663881_fix'
  tag 'documentable'
  tag legacy: ['SV-98993', 'V-88343']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
