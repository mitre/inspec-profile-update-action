control 'SV-98943' do
  title 'The vROps PostgreSQL DB must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*port\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If the port is set to "5432", this is NOT a finding.

If the port is not set to "5432" and if the ISSO does not have documentation of an approved variance for using a non-standard port, this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET port TO '5432';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88293'
  tag rid: 'SV-98943r1_rule'
  tag stig_id: 'VROM-PG-000405'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-95035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
