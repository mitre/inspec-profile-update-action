control 'SV-80459' do
  title 'Trend Deep Security must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are off-loaded onto a different system or media than the system being audited.

Verify that audit records are off-loaded by configuring the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration> > System Settings >> SIEM tab.
2. In the System Event Notification (from the Manager) area, verify the “Forward System Events to a remote computer (via Syslog) option” is Enabled.
3. Verify the IP address to the selected host name is entered.
4. Verify UDP port 514 or agency selected port is provided.
5. Verify the appropriate Syslog facility and Common Event Settings

If any of these settings are missing from the SIEM configuration, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to off-load audit records onto a different system or media than the system being audited.

To configure the Manager to instruct all managed computers to use Syslog:

1. Go to the Administration >> System Settings >> SIEM tab.
2. In the System Event Notification (from the Manager) area, set the Forward System Events to a remote computer (via Syslog) option.
3. Type the hostname or the IP address of the Syslog computer.
4. Enter which UDP port to use (usually 514).
5. Select which Syslog facility to use.
6. Select the "Common Event Format" log format. (The "Basic Syslog" format is listed only for legacy support and should not be used for new integrations.)'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65969'
  tag rid: 'SV-80459r1_rule'
  tag stig_id: 'TMDS-00-000265'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-72045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
