control 'SV-255244' do
  title 'SSMC must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.

'
  desc 'check', 'Verify SSMC synchronizes system clocks to the authoritative time source by performing the following: 

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o configure_ntp -a status

NTP service is configured

If the NTP service is not configured, this is a finding.'
  desc 'fix', 'Configure SSMC to synchronize system clock to the authoritative time source by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Edit /ssmc/conf/security_config.properties using vi editor and configure the IP address of one or more time servers with which the system clock needs to be synchronized via NTP. Save and exit.

3. Execute the following command: 

$ sudo /ssmc/bin/config_security.sh -o configure_ntp -a set -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58857r869880_chk'
  tag severity: 'medium'
  tag gid: 'V-255244'
  tag rid: 'SV-255244r869882_rule'
  tag stig_id: 'SSMC-OS-010260'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-58801r869881_fix'
  tag satisfies: ['SRG-OS-000356-GPOS-00144', 'SRG-OS-000355-GPOS-00143']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end
