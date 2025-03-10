control 'SV-246937' do
  title 'ONTAP must use internal system clocks to generate time stamps for audit records.'
  desc "In order to determine what is happening within the network infrastructure or to resolve and trace an attack, the network device must support the organization's capability to correlate the audit log data from multiple network devices to acquire a clear understanding of events. In order to correlate auditable events, time stamps are needed on all of the log records.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. (Note that the internal clock must be synchronized with authoritative time sources by other requirements.)"
  desc 'check', 'Use "cluster time-service ntp server show" to see the current network time protocol configuration for ONTAP.

If ONTAP does not use internal system clocks synchronized to an authoritative time source to generate time stamps for audit records, this is a finding.'
  desc 'fix', 'Configure network time protocol for ONTAP with "cluster time-service ntp server create -server <IP address>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50369r769141_chk'
  tag severity: 'medium'
  tag gid: 'V-246937'
  tag rid: 'SV-246937r769143_rule'
  tag stig_id: 'NAOT-AU-000005'
  tag gtitle: 'SRG-APP-000116-NDM-000234'
  tag fix_id: 'F-50323r769142_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
