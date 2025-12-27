control 'SV-256593' do
  title 'VMware Postgres configuration files must not be accessible by unauthorized users.'
  desc 'VMware Postgres has a few configuration files that directly control the security posture of the database management system (DBMS). Protecting these files from unauthorized access and modification is fundamental to ensuring the security of VMware Postgres.

'
  desc 'check', "At the command prompt, run the following command:

# find /storage/db/vpostgres/*conf* -xdev -type f -a '(' -not -perm 600 -o -not -user vpostgres -o -not -group vpgmongrp ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod 600 <file>
# chown vpostgres:vpgmongrp <file>

Note: Replace <file> with the file that has incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA PostgreSQL'
  tag check_id: 'C-60268r887563_chk'
  tag severity: 'medium'
  tag gid: 'V-256593'
  tag rid: 'SV-256593r887565_rule'
  tag stig_id: 'VCPG-70-000003'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-60211r887564_fix'
  tag satisfies: ['SRG-APP-000090-DB-000065', 'SRG-APP-000121-DB-000202', 'SRG-APP-000122-DB-000203', 'SRG-APP-000123-DB-000204', 'SRG-APP-000380-DB-000360']
  tag 'documentable'
  tag cci: ['CCI-000171', 'CCI-001493', 'CCI-001494', 'CCI-001495', 'CCI-001813']
  tag nist: ['AU-12 b', 'AU-9 a', 'AU-9', 'AU-9', 'CM-5 (1) (a)']
end
