control 'SV-239784' do
  title 'The vROps PostgreSQL DB must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the DBMS must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the DBMS must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_truncate_on_rotation\b' /storage/db/vcops/vpostgres/data/postgresql.conf

If log_truncate_on_rotation is not set to "on", this is a finding.)
  desc 'fix', 'At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_truncate_on_rotation TO on;"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();"'
  impact 0.3
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43017r663727_chk'
  tag severity: 'low'
  tag gid: 'V-239784'
  tag rid: 'SV-239784r879571_rule'
  tag stig_id: 'VROM-PG-000095'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-42976r663728_fix'
  tag 'documentable'
  tag legacy: ['SV-98891', 'V-88241']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
