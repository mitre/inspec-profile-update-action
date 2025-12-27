control 'SV-38289' do
  title 'The system clock must be synchronized continuously or at least daily.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. Internal system clocks tend to drift and require periodic resynchronization to ensure their accuracy. Software, such as ntpd, can be used to continuously synchronize the system clock with authoritative sources. Alternatively, the system may be synchronized periodically, with a maximum of one day between synchronizations.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'Check the root crontab for ntpdate jobs running at least daily.
# crontab -l | grep ntpdate
columns 3, 4, and 5 must be an asterisk (*) for the job to be run daily.
If this job exists, this is not a finding.

OR

Verify the auto-startup of (x)ntpd in /etc/rc.config.d/netdaemons.
# cat /etc/rc.config.d/netdaemons | grep -v "^#" | grep -i "XNTPD=1"

Check the system for a running NTP daemon, which is the preferred method. 

# ps -ef | grep ntp

If an (x)ntpd process exists, this is not a finding.  Otherwise, this is a finding.'
  desc 'fix', 'Enable the NTP daemon for continuous synchronization.

Edit /etc/rc.config.d/netdaemons and set XNTPD=1
Edit /etc/ntp.conf and add the ntp server entry.
Then:

# /sbin/init.d/xntpd start

OR

Add a daily or more frequent cronjob to perform synchronization using ntpdate.

NOTE: While it is possible to run ntpdate from a cron script, it is important to mention that ntpdate with contrived cron scripts is no substitute for the NTP daemon, which uses sophisticated algorithms to maximize accuracy and reliability while minimizing resource use. Finally, since ntpdate polling does not discipline the host clock frequency as does (x)ntpd, the accuracy using ntpdate is limited. The process of passively listening for NTP broadcasts (i.e., placing the line broadcastclient yes in the /etc/ntp.conf file) is preferred over any procedural form of direct server polling for a large network with many nodes needing to be time-synchronized. This method is preferred because it significantly reduces the network traffic load related to NTP.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36234r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22290'
  tag rid: 'SV-38289r1_rule'
  tag stig_id: 'GEN000241'
  tag gtitle: 'GEN000241'
  tag fix_id: 'F-31493r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
