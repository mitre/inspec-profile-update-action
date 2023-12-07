control 'SV-95587' do
  title 'AAA Services must be configured to use internal system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose. Synchronizing the internal clock using NTP provides uniformity for all system clocks over a network. NTP provides an efficient and scalable method for network devices to synchronize to an accurate time source.'
  desc 'check', 'Verify AAA Services are configured to use internal system clocks to generate time stamps for audit records.

If AAA Services are not configured to use internal system clocks to generate time stamps for audit records, this is a finding.'
  desc 'fix', 'Configure AAA Services to use internal system clocks to generate time stamps for audit records.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80877'
  tag rid: 'SV-95587r1_rule'
  tag stig_id: 'SRG-APP-000116-AAA-000320'
  tag gtitle: 'SRG-APP-000116-AAA-000320'
  tag fix_id: 'F-87731r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
