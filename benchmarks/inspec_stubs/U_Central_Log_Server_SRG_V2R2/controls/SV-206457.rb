control 'SV-206457' do
  title 'The Central Log Server must be configured to use internal system clocks to generate time stamps for log records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server uses internal system clocks to generate time stamps for log records.

If the Central Log Server is not configured to use internal system clocks to generate time stamps for log records, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to use internal system clocks to generate time stamps for log records.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6717r285615_chk'
  tag severity: 'low'
  tag gid: 'V-206457'
  tag rid: 'SV-206457r395817_rule'
  tag stig_id: 'SRG-APP-000116-AU-000270'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-6717r285616_fix'
  tag 'documentable'
  tag legacy: ['SV-95837', 'V-81123']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
