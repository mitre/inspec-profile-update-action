control 'SV-95865' do
  title 'The Central Log Server must be configured to send an immediate alert to the System Administrator (SA) or Information System Security Officer (ISSO) if communication with the host and devices within its scope of coverage is lost.'
  desc 'If the system were to continue processing after audit failure, actions could be taken on the system that could not be tracked and recorded for later forensic analysis. To perform this function, some type of heartbeat configuration with all of the devices and hosts must be configured.

Because of the importance of ensuring mission/business continuity, organizations may determine that the nature of the audit failure is not so severe that it warrants a complete shutdown of the application supporting the core organizational missions/business operations. In those instances, partial application shutdowns or operating in a degraded mode may be viable alternatives. 

This requirement applies to each audit data storage repository (i.e., distinct information system component where log records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Examine the configuration.

Verify the system is configured to send an immediate alert to the SA or ISSO if communication with the host and devices within its scope of coverage is lost.

If the Central Log Server is not configured to send an immediate alert to the SA or ISSO if communication with the host and devices within its scope of coverage is lost, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to send an immediate alert to the SA or ISSO if communication with the host and devices within its scope of coverage is lost.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80813r1_chk'
  tag severity: 'low'
  tag gid: 'V-81151'
  tag rid: 'SV-95865r1_rule'
  tag stig_id: 'SRG-APP-000361-AU-000140'
  tag gtitle: 'SRG-APP-000361-AU-000140'
  tag fix_id: 'F-87927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
