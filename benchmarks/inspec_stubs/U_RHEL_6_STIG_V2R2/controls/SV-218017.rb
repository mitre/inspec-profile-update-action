control 'SV-218017' do
  title 'The ntpdate service must not be running.'
  desc 'The "ntpdate" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.'
  desc 'check', 'To check that the "ntpdate" service is disabled in system boot configuration, run the following command: 

# chkconfig "ntpdate" --list

Output should indicate the "ntpdate" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "ntpdate" --list
"ntpdate" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ntpdate" is disabled through current runtime configuration: 

# service ntpdate status

If the service is disabled the command will return the following output: 

ntpdate is stopped


If the service is running, this is a finding.'
  desc 'fix', 'The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in "/etc/ntp/step-tickers" or "/etc/ntp.conf" and then sets the local hardware clock to the newly synchronized system time. The "ntpdate" service can be disabled with the following commands: 

# chkconfig ntpdate off
# service ntpdate stop'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19498r377066_chk'
  tag severity: 'low'
  tag gid: 'V-218017'
  tag rid: 'SV-218017r603264_rule'
  tag stig_id: 'RHEL-06-000265'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-19496r377067_fix'
  tag 'documentable'
  tag legacy: ['SV-50445', 'V-38644']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
