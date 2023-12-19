control 'SV-91643' do
  title 'The DBN-6300 must use internal system clocks to generate time stamps for audit records.'
  desc "In order to determine what is happening within the network infrastructure or to resolve and trace an attack, the network device must support the organization's capability to correlate the audit log data from multiple network devices to acquire a clear understanding of events. In order to correlate auditable events, time stamps are needed on all of the log records.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. (Note that the internal clock is required to be synchronized with authoritative time sources by other requirements.)"
  desc 'check', 'Verify the configuration of the NTP server.

Navigate to Settings >> Initial Configuration >> Time.

View the "Time" settings window.

If an NTP server address is not configured, this is a finding.'
  desc 'fix', 'Configure the NTP server on the device. The time difference is part of the NTP protocol and is not configurable.

Navigate to Settings >> Initial Configuration >> Time.

In the "Time" settings window, select the "NTP" button and enter the NTP server address.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76947'
  tag rid: 'SV-91643r1_rule'
  tag stig_id: 'DBNW-DM-000036'
  tag gtitle: 'SRG-APP-000116-NDM-000234'
  tag fix_id: 'F-83643r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
