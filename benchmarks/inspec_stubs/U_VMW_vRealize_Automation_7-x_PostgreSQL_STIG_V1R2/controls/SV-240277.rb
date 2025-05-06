control 'SV-240277' do
  title 'The vRA PostgreSQL configuration file must not be accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/*conf*

If the permissions on any of the listed files are not "600", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43510r668673_chk'
  tag severity: 'medium'
  tag gid: 'V-240277'
  tag rid: 'SV-240277r879560_rule'
  tag stig_id: 'VRAU-PG-000025'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-43469r668674_fix'
  tag 'documentable'
  tag legacy: ['SV-99979', 'V-89329']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
