control 'SV-213566' do
  title 'The EDB Postgres Advanced Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Run the command "ls -al <postgresql data directory>/postgresql*.conf" to show file permissions.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

If the files are not owned by enterprisedb(user)/enterprisedb(group) or does not have RW permission for the user only, this is a finding.'
  desc 'fix', 'Run these commands: 

1) "chown enterprisedb <postgresql data directory>/postgresql*.conf" 

2) "chgrp enterprisedb <postgresql data directory>/postgresql*.conf"

3) "chmod 600 <postgresql data directory>/postgresql*.conf"

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14788r290010_chk'
  tag severity: 'medium'
  tag gid: 'V-213566'
  tag rid: 'SV-213566r508024_rule'
  tag stig_id: 'PPS9-00-001100'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-14786r290011_fix'
  tag 'documentable'
  tag legacy: ['V-68885', 'SV-83489']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
