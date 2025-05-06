control 'SV-221709' do
  title 'The Oracle Linux operating system must be configured so that designated personnel are notified if baseline configurations are changed in an unauthorized manner.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.

Check to see if AIDE is installed on the system with the following command:

# yum list installed aide

If AIDE is not installed, ask the SA how file integrity checks are performed on the system. 

Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.

Check the cron directories for a "crontab" script file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# ls -al /etc/cron.* | grep aide
-rwxr-xr-x 1 root root 32 Jul 1 2011 aide

# grep aide /etc/crontab /var/spool/cron/root
/etc/crontab: 30 04 * * * root /usr/sbin/aide  --check
/var/spool/cron/root: 30 04 * * * /usr/sbin/aide --check

AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:

# more /etc/cron.daily/aide
#!/bin/bash

/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil

If the file integrity application does not notify designated personnel of changes, this is a finding.'
  desc 'fix', 'Configure the operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel with the use of the cron system. 

The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis. 

# more /etc/cron.daily/aide

/usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36272r602410_chk'
  tag severity: 'medium'
  tag gid: 'V-221709'
  tag rid: 'SV-221709r853669_rule'
  tag stig_id: 'OL07-00-020040'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-36236r602411_fix'
  tag 'documentable'
  tag legacy: ['SV-108261', 'V-99157']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
