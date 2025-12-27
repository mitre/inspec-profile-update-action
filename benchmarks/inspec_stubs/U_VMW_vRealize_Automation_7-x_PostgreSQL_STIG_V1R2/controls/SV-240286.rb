control 'SV-240286' do
  title 'vRA PostgreSQL database log file data must contain required data elements.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of group account users.'
  desc 'check', %q(At the command prompt, execute the following command:

# grep '^\s*log_line_prefix\b' /storage/db/pgdata/postgresql.conf

If "log_line_prefix" is not set to "%m %d %u %r %p %l %c", this is a finding.)
  desc 'fix', %q(At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "ALTER SYSTEM SET log_line_prefix TO '%m %d %u %r %p %l %c';"
# /opt/vmware/vpostgres/current/bin/psql -U postgres -c "SELECT pg_reload_conf();")
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43519r668700_chk'
  tag severity: 'medium'
  tag gid: 'V-240286'
  tag rid: 'SV-240286r879569_rule'
  tag stig_id: 'VRAU-PG-000080'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-43478r668701_fix'
  tag 'documentable'
  tag legacy: ['SV-99999', 'V-89349']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
