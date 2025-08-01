control 'SV-239198' do
  title 'VMware Postgres configuration files must not be accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

"
  desc 'check', "At the command prompt, enter the following command:

# find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group users ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>
# chown vpostgres:users <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42431r678965_chk'
  tag severity: 'medium'
  tag gid: 'V-239198'
  tag rid: 'SV-239198r678967_rule'
  tag stig_id: 'VCPG-67-000003'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-42390r678966_fix'
  tag satisfies: ['SRG-APP-000090-DB-000065', 'SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
