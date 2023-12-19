control 'SV-217148' do
  title 'Advanced Intrusion Detection Environment (AIDE) must verify the baseline SUSE operating system configuration at least weekly.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the SUSE operating system. Changes to SUSE operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the SUSE operating system. The SUSE operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrator (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the SUSE operating system checks the baseline configuration for unauthorized changes at least once weekly.

Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.

Check to see if the "aide" package is installed on the system with the following command:

# sudo zypper if aide | grep "Installed"

Installed: Yes

If the "aide" package is not installed, ask the System Administrator (SA) how file integrity checks are performed on the system.

Check for a "crontab" that controls the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

# sudo crontab -l

0 0 * * 6 /usr/bin/aide --check | /bin/mail -s "aide integrity check run for <system name>" root@notareal.email

If the file integrity application does not exist, or a "crontab" entry does not exist, check the cron directories for a script that runs the file integrity application:

# ls -al /etc/cron.daily /etc/cron.weekly

Inspect the file and ensure that the file integrity tool is being executed.

If a file integrity tool is not configured in the crontab or in a script that runs at least weekly, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to check the baseline configuration for unauthorized changes at least once weekly.

If the "aide" package is not installed, install it with the following command:

# sudo zypper in aide

Configure the file integrity tool to automatically run on the system at least weekly. 

The following example output is generic. It will set cron to run AIDE weekly, but other file integrity tools may be used:

# sudo crontab -l

0 0 * * 6 /usr/sbin/aide --check | /bin/mail -s "aide integrity check run for <system name>" root@notareal.email'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18376r369600_chk'
  tag severity: 'medium'
  tag gid: 'V-217148'
  tag rid: 'SV-217148r603262_rule'
  tag stig_id: 'SLES-12-010500'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-18374r369601_fix'
  tag 'documentable'
  tag legacy: ['V-77151', 'SV-91847']
  tag cci: ['CCI-002696', 'CCI-002699', 'CCI-001744']
  tag nist: ['SI-6 a', 'SI-6 b', 'CM-3 (5)']
end
