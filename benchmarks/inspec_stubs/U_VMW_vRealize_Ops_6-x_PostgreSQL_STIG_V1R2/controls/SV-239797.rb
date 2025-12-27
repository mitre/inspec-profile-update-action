control 'SV-239797' do
  title 'If passwords are used for authentication, the vROps PostgreSQL DB must transmit only encrypted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.

DBMS passwords sent in clear text format across the network are vulnerable to discovery by unauthorized users. Disclosure of passwords may easily lead to unauthorized access to the database.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*ssl\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If ssl is not set to "on", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET ssl TO 'on';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43030r663766_chk'
  tag severity: 'medium'
  tag gid: 'V-239797'
  tag rid: 'SV-239797r879609_rule'
  tag stig_id: 'VROM-PG-000195'
  tag gtitle: 'SRG-APP-000172-DB-000075'
  tag fix_id: 'F-42989r663767_fix'
  tag 'documentable'
  tag legacy: ['SV-98917', 'V-88267']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
