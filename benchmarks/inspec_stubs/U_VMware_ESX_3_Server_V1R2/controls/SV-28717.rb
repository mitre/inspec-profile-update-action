control 'SV-28717' do
  title 'The system must use at least two time sources for clock synchronization.'
  desc "A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  For redundancy, two time sources are required so that synchronization continues to function if one source fails.  

If the system is completely isolated (that is, it has no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary.  If the system is completely isolated, this requirement is not applicable.

NOTE:  For the network time protocol (NTP), the requirement is two servers, but it is recommended to configure at least four distinct time servers which allow NTP to effectively exclude a time source that is not consistent with the others.  The system's local clock must be excluded from the count of time sources."
  desc 'check', "Check the root crontab for ntpdate entries.
# crontab -l | grep ntpdate
If the ntpdate command is not invoked with at least two external NTP servers listed, this is a finding.

Check the NTP daemon configuration for at least two external servers.
# grep ^server ntp.conf | egrep -v '(127.127.1.1|127.127.1.0)'
If less than two servers or external reference clocks (127.127.x.x other than 127.127.1.0 or 127.127.1.1) are listed, this is a finding."
  desc 'fix', 'If using ntpdate, add additional NTP servers to the cron job running ntpdate.

If using the NTP daemon, add an additional "server" line to ntp.conf for each additional NTP server.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29012r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22291'
  tag rid: 'SV-28717r1_rule'
  tag stig_id: 'GEN000242'
  tag gtitle: 'GEN000242'
  tag fix_id: 'F-26022r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000160']
  tag nist: ['AU-8 (1)']
end
