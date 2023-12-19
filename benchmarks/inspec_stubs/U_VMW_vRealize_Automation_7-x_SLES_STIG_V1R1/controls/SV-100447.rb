control 'SV-100447' do
  title 'The SLES for vRealize must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.'
  desc 'check', 'Run the following command to determine the current status of the "ntpd" service: 

# service ntp status

If the service is configured, the command should show a list of the ntp servers and the status of the synchronization.

If it does not, this is a finding.'
  desc 'fix', 'The "ntp" service can be enabled with the following command: 

# chkconfig ntp on 
# service ntp start

Configure the time server for the authoritative time source with the following steps:

1. Edit /etc/ntp.conf and locate the "server" entry.
2. Replace the address with the address of the authoritative time source.
3. Save the /etc/ntp.conf file.
4. Restart the ntp daemon with /etc/init.d/ntp start.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89489r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89797'
  tag rid: 'SV-100447r1_rule'
  tag stig_id: 'VRAU-SL-001130'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-96539r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
