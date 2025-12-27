control 'SV-44774' do
  title 'The system must use time sources that are local to the enclave.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  The network architecture should provide multiple time servers within an enclave providing local service to the enclave and synchronize with time sources outside of the enclave.

If this server is an enclave time server, this requirement is not applicable.

If the system is completely isolated (i.e., it has no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary.  If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'Check the root crontab (crontab -l) and the global crontabs in /etc/crontab, /etc/cron.d/*, or scripts in the /etc/cron.daily directory for the presence of an "ntpd -qg" job. If the "ntpd -qg" command is invoked with NTP servers outside of the enclave, this is a finding.

Check the NTP daemon configuration for NTP servers.
# grep ^server /etc/ntp.conf | grep -v 127.127.1.1
If an NTP server is listed outside of the enclave, this is a finding.'
  desc 'fix', 'If using "ntpd -qg", remove NTP servers external to the enclave from the cron job running "ntpd -qg".

If using the NTP daemon, remove the "server" line from /etc/ntp.conf for each NTP server external to the enclave.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42280r1_chk'
  tag severity: 'low'
  tag gid: 'V-22292'
  tag rid: 'SV-44774r1_rule'
  tag stig_id: 'GEN000244'
  tag gtitle: 'GEN000244'
  tag fix_id: 'F-38225r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000160']
  tag nist: ['AU-8 (1)']
end
