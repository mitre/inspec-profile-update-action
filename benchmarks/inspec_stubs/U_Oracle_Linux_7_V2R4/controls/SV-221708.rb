control 'SV-221708' do
  title 'The Oracle Linux operating system must be configured so that a file integrity tool verifies the baseline operating system configuration at least weekly.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

"
  desc 'check', 'Verify the operating system routinely checks the baseline configuration for unauthorized changes.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.

Check to see if AIDE is installed on the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the SA how file integrity checks are performed on the system.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.

Check the cron directories for a script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# ls -al /etc/cron.* | grep aide
-rwxr-xr-x 1 root root 29 Nov 22 2015 aide

# grep aide /etc/crontab /var/spool/cron/root
/etc/crontab: 30 04 * * * root /usr/sbin/aide --check
/var/spool/cron/root: 30 04 * * * /usr/sbin/aide --check

If the file integrity application does not exist, or a script file controlling the execution of the file integrity application does not exist, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to run automatically on the system at least weekly. The following example output is generic. It will set cron to run AIDE daily, but other file integrity tools may be used: 

# more /etc/cron.daily/aide
#!/bin/bash

/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36271r602407_chk'
  tag severity: 'medium'
  tag gid: 'V-221708'
  tag rid: 'SV-221708r603260_rule'
  tag stig_id: 'OL07-00-020030'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-36235r602408_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150 and SRG-OS-000446-GPOS-00200']
  tag 'documentable'
  tag legacy: ['V-99155', 'SV-108259']
  tag cci: ['CCI-001744', 'CCI-002699']
  tag nist: ['CM-3 (5)', 'SI-6 b']
end
