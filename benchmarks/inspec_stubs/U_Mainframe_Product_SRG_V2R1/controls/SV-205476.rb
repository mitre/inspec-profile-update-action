control 'SV-205476' do
  title 'The Mainframe Products must use internal system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate. Applications can use the capability of an operating system or purpose-built module for this purpose.'
  desc 'check', 'Examine installation and configuration settings.

If the Mainframe Product does not use the z/OS system clock for audit time stamps, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to use the z/OS system clock for audit time stamps.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5742r299661_chk'
  tag severity: 'medium'
  tag gid: 'V-205476'
  tag rid: 'SV-205476r395817_rule'
  tag stig_id: 'SRG-APP-000116-MFP-000171'
  tag gtitle: 'SRG-APP-000116'
  tag fix_id: 'F-5742r299662_fix'
  tag 'documentable'
  tag legacy: ['SV-82779', 'V-68289']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
