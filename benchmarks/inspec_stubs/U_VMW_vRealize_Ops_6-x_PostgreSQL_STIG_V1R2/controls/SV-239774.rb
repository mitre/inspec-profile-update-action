control 'SV-239774' do
  title 'The vROps PostgreSQL DB must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/*conf*

If the permissions on any of the listed files are not "600" or more restrictive, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43007r663697_chk'
  tag severity: 'medium'
  tag gid: 'V-239774'
  tag rid: 'SV-239774r879560_rule'
  tag stig_id: 'VROM-PG-000030'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-42966r663698_fix'
  tag 'documentable'
  tag legacy: ['SV-98869', 'V-88219']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
