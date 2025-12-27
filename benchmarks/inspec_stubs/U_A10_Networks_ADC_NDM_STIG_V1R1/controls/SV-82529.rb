control 'SV-82529' do
  title 'The A10 Networks ADC must produce audit log records containing information (FQDN, unique hostname, management or loopback IP address) to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event. The source may be a component, module, or process within the device or an external session, administrator, or device. Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.

When the event log or system log is written to a syslog server, the hostname is included with each record.'
  desc 'check', 'Observe someone logging onto the device. The prompt will appear after a successful logon.

If the prompt is not a unique hostname assigned by the organization, this is a finding.

Note: The device automatically includes the hostname in each Syslog message.'
  desc 'fix', 'The following command will change the hostname:
hostname [string]

The string can contain 1 to 31 characters and can contain the following characters: a-z A-Z 0-9 - . ( )

Note: The device automatically includes the hostname in each Syslog message.'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68599r1_chk'
  tag severity: 'low'
  tag gid: 'V-68039'
  tag rid: 'SV-82529r1_rule'
  tag stig_id: 'AADC-NM-000029'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-74155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
