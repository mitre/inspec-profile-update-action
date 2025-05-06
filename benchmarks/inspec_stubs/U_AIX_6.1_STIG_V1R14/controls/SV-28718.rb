control 'SV-28718' do
  title 'The system must use time sources local to the enclave.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  The network architecture should provide multiple time servers within an enclave providing local service to the enclave and synchronize with time sources outside of the enclave.

If this server is an enclave time server, this requirement is not applicable.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary.  If the system is completely isolated, this requirement is not applicable.'
  desc 'check', "Check the root crontab for ntpdate entries.
# crontab -l | grep ntpdate
If the ntpdate command is invoked with NTP servers outside of the enclave, this is a finding.

Check the NTP daemon configuration.
# grep '^server' ntp.conf
If an NTP server is listed outside of the enclave, this is a finding."
  desc 'fix', 'If using ntpdate, remove NTP servers external to the enclave from the cron job running ntpdate.

If using the NTP daemon, remove the server line from ntp.conf for each NTP server external to the enclave.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-29013r1_chk'
  tag severity: 'low'
  tag gid: 'V-22292'
  tag rid: 'SV-28718r1_rule'
  tag stig_id: 'GEN000244'
  tag gtitle: 'GEN000244'
  tag fix_id: 'F-26023r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000160']
  tag nist: ['AU-8 (1)']
end
