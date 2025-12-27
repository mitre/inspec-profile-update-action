control 'SV-28719' do
  title 'The system time synchronization method must use cryptographic algorithms to verify the authenticity and integrity of the time data.'
  desc 'A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems.  If an illicit time source is used for synchronization, the integrity of system logs and the security of the system could be compromised.'
  desc 'check', "Check the root crontab for ntpdate entries.
# crontab -l | grep ntpdate
If the ntpdate command is not invoked with the -a parameter, this is a finding.

Check the NTP daemon configuration.
# grep ^server ntp.conf | grep -v '( key | autokey )'
If server lines are present without key or autokey options, this is a finding."
  desc 'fix', 'If using ntpdate, add the -a option with a key to the cron job running ntpdate.

If using the NTP daemon, add the key or autokey options, as appropriate, to each server line in ntp.conf for each NTP server not configured for authentication.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29014r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22293'
  tag rid: 'SV-28719r1_rule'
  tag stig_id: 'GEN000246'
  tag gtitle: 'GEN000246'
  tag fix_id: 'F-26024r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001145']
  tag nist: ['SC-13 (1)']
end
