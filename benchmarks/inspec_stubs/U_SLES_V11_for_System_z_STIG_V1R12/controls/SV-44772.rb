control 'SV-44772' do
  title 'The system clock must be synchronized continuously, or at least daily.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  Internal system clocks tend to drift and require periodic resynchronization to ensure their accuracy.  Software, such as ntpd, can be used to continuously synchronize the system clock with authoritative sources.  Alternatively, the system may be synchronized periodically, with a maximum of one day between synchronizations.

If the system is completely isolated (i.e., it has no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'Check the root crontab (crontab -l) and the global crontabs in /etc/crontab, /etc/cron.d/* for the presence of an "ntpd -qg" job to run at least daily, which should have asterisks (*) in columns 3, 4, and 5.

Check the daily cron directory (/etc/cron.daily) for any script running "ntpd -qg".

Check for a running NTP daemon.
# ps ax | grep ntpd

If none of the above checks are successful, this is a finding.'
  desc 'fix', 'Enable the NTP daemon for continuous synchronization.
# rcntp ; insserv ntp

OR

Add a daily or more frequent cronjob to perform synchronization using ntpdate.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42278r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22290'
  tag rid: 'SV-44772r1_rule'
  tag stig_id: 'GEN000241'
  tag gtitle: 'GEN000241'
  tag fix_id: 'F-38223r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
