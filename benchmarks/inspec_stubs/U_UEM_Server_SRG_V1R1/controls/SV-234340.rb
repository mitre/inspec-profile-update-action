control 'SV-234340' do
  title 'The UEM server must use host operating system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. 

'
  desc 'check', 'Verify the UEM server uses host operating system clocks to generate time stamps for audit records.

If the UEM server does not use host operating system clocks to generate time stamps for audit records, this is a finding'
  desc 'fix', 'Configure the UEM server to use host operating system clocks to generate time stamps for audit records.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37525r614030_chk'
  tag severity: 'medium'
  tag gid: 'V-234340'
  tag rid: 'SV-234340r617403_rule'
  tag stig_id: 'SRG-APP-000116-UEM-000067'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-37490r614031_fix'
  tag satisfies: ['OE.TIMESTAMP', 'FAU_GEN.1.2(1)']
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
