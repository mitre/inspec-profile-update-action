control 'SV-80527' do
  title 'Trend Deep Security must, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.

Verify that audit records are off-loaded by configuring the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration >> System Settings >> SIEM tab.
2. In the System Event Notification (from the Manager) area, verify the “Forward System Events to a remote computer (via Syslog)" box is checked. 
3. Verify the IP address to the selected host name is entered.
4. Verify UDP port 514 or agency selected port is provided.
5. Verify the appropriate Syslog facility and Common Event Settings

If any of these settings are missing from the SIEM configuration, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly.

To configure the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration >> System Settings >> SIEM tab.
2. In the “System Event Notification (from the Manager)” area, check the “Forward System Events to a remote computer (via Syslog)” box.
3. Type the hostname or the IP address of the Syslog computer.
4. Enter which UDP port to use (usually 514).
5. Select which Syslog facility to use.
6. Select the "Common Event Format" log format. (The "Basic Syslog" format is listed only for legacy support and should not be used for new integrations).'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66685r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66037'
  tag rid: 'SV-80527r1_rule'
  tag stig_id: 'TMDS-00-000410'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-72113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
