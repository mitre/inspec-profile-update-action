control 'SV-202039' do
  title 'The network device must use internal system clocks to generate time stamps for audit records.'
  desc "In order to determine what is happening within the network infrastructure or to resolve and trace an attack, the network device must support the organization's capability to correlate the audit log data from multiple network devices to acquire a clear understanding of events. In order to correlate auditable events, time stamps are needed on all of the log records.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose.  (Note that the internal clock is required to be synchronized with authoritative time sources by other requirements.)"
  desc 'check', 'Determine if the network device uses internal system clocks to generate time stamps for audit records. This requirement may be verified by demonstration, configuration, or validated test results. If the network device does not use internal system clocks to generate time stamps for audit records, this is a finding.'
  desc 'fix', 'Configure the network device to use internal system clocks to generate time stamps for audit records.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2165r381680_chk'
  tag severity: 'medium'
  tag gid: 'V-202039'
  tag rid: 'SV-202039r395817_rule'
  tag stig_id: 'SRG-APP-000116-NDM-000234'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-2166r381681_fix'
  tag 'documentable'
  tag legacy: ['SV-69411', 'V-55165']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
