control 'SV-203615' do
  title 'The operating system must use internal system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

If the internal clock is not used, the system may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate.'
  desc 'check', 'Verify the operating system uses internal system clocks to generate time stamps for audit records. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to use internal system clocks to generate time stamps for audit records.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3740r557101_chk'
  tag severity: 'medium'
  tag gid: 'V-203615'
  tag rid: 'SV-203615r557103_rule'
  tag stig_id: 'SRG-OS-000055-GPOS-00026'
  tag gtitle: 'SRG-OS-000055'
  tag fix_id: 'F-3740r557102_fix'
  tag 'documentable'
  tag legacy: ['V-56669', 'SV-70929']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
