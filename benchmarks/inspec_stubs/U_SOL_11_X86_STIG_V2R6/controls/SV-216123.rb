control 'SV-216123' do
  title 'Unauthorized use of the at or cron capabilities must not be permitted.'
  desc 'On many systems, only the system administrator needs the ability to schedule jobs.

Even though a given user is not listed in the "cron.allow" file, cron jobs can still be run as that user. The "cron.allow" file only controls administrative access to the "crontab" command for scheduling and modifying cron jobs. Much more effective access controls for the cron system can be obtained by using Role-Based Access Controls (RBAC).'
  desc 'check', %q(Check that "at" and "cron" users are configured correctly.

# ls /etc/cron.d/cron.deny

If cron.deny exists, this is a finding.

# ls /etc/cron.d/at.deny

If at.deny exists, this is a finding.

# cat /etc/cron.d/cron.allow

cron.allow should have a single entry for "root", or the cron.allow file is removed if using RBAC.  
 
If any accounts other than root that are listed and they are not properly documented with the IA staff, this is a finding.

# wc -l /etc/cron.d/at.allow | awk '{ print $1 }'

If the output is non-zero, this is a finding, or the at.allow file is removed if using RBAC.)
  desc 'fix', 'The root role is required.

Modify the cron configuration files.

# mv /etc/cron.d/cron.deny /etc/cron.d/cron.deny.temp
# mv /etc/cron.d/at.deny /etc/cron.d/at.deny.temp

Skip the remaining steps only if using the “solaris.jobs.user” RBAC role.

# echo root > /etc/cron.d/cron.allow
# cp /dev/null /etc/cron.d/at.allow
# chown root:root /etc/cron.d/cron.allow /etc/cron.d/at.allow
# chmod 400 /etc/cron.d/cron.allow /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17361r462445_chk'
  tag severity: 'medium'
  tag gid: 'V-216123'
  tag rid: 'SV-216123r603268_rule'
  tag stig_id: 'SOL-11.1-040420'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17359r462446_fix'
  tag 'documentable'
  tag legacy: ['SV-60997', 'V-48125']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
