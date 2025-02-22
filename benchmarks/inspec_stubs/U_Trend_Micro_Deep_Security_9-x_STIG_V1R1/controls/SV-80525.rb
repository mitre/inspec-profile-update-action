control 'SV-80525' do
  title 'Trend Deep Security must generate audit records for all kernel module load, unload, and restart events and, also for all program initiations.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Trend Deep Security server to ensure audit records are generated for all kernel module load, unload, and restart events and, also for all program initiations.

Verify that audit records are off-loaded by configuring the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration >> System Settings >> SIEM tab.
2. In the System Event Notification (from the Manager) area, verify the “Forward System Events to a remote computer (via Syslog)" box is checked. 
3. Verify the IP address to the selected host name is entered.
4. Verify UDP port 514 or agency selected port is provided.
5. Verify the appropriate Syslog facility and Common Event Settings

If any of these settings are missing from the SIEM configuration, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to generate audit records for all kernel module load, unload, and restart events and, also for all program initiations.

To configure the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration >> System Settings >> SIEM tab.
2. In the “System Event Notification (from the Manager)” area, check the “Forward System Events to a remote computer (via Syslog)” box.
3. Type the hostname or the IP address of the Syslog computer.
4. Enter which UDP port to use (usually 514).
5. Select which Syslog facility to use.
6. Select the "Common Event Format" log format. (The "Basic Syslog" format is listed only for legacy support and should not be used for new integrations).'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66683r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66035'
  tag rid: 'SV-80525r1_rule'
  tag stig_id: 'TMDS-00-000405'
  tag gtitle: 'SRG-APP-000510'
  tag fix_id: 'F-72111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
