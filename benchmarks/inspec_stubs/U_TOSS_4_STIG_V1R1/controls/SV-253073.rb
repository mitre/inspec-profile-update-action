control 'SV-253073' do
  title 'TOSS must disable network management of the chrony daemon.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time when a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Not exposing the management interface of the chrony daemon on the network diminishes the attack space.

TOSS utilizes the "timedatectl" command to view the status of the "systemd-timesyncd.service." The "timedatectl" status will display the local time, UTC, and the offset from UTC.

Note that USNO offers authenticated NTP service to DoD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/dod-customers for more information.'
  desc 'check', %q(Verify TOSS disables network management of the chrony daemon with the following command:

$ sudo grep -w 'cmdport' /etc/chrony.conf

cmdport 0

If the "cmdport" option is not set to "0", is commented out or missing, this is a finding.)
  desc 'fix', 'Configure the operating system disable network management of the chrony daemon by adding/modifying the following line in the /etc/chrony.conf file.

cmdport 0'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56526r824889_chk'
  tag severity: 'medium'
  tag gid: 'V-253073'
  tag rid: 'SV-253073r824891_rule'
  tag stig_id: 'TOSS-04-040180'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56476r824890_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
