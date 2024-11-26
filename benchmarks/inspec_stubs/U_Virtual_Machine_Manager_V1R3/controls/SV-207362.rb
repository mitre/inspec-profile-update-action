control 'SV-207362' do
  title 'The VMM must use internal system clocks to generate time stamps for audit records.'
  desc 'Without an internal clock used as the reference for the time stored on each event to provide a trusted common reference for the time, forensic analysis would be impeded. Determining the correct time a particular event occurred on a VMM is critical when conducting forensic analysis and investigating system events.

If the internal clock is not used, the VMM may not be able to provide time stamps for log messages. Additionally, externally generated time stamps may not be accurate.'
  desc 'check', 'Verify the VMM uses internal system clocks to generate time stamps for audit records. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to use internal system clocks to generate time stamps for audit records.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7619r365496_chk'
  tag severity: 'medium'
  tag gid: 'V-207362'
  tag rid: 'SV-207362r378646_rule'
  tag stig_id: 'SRG-OS-000055-VMM-000250'
  tag gtitle: 'SRG-OS-000055'
  tag fix_id: 'F-7619r365497_fix'
  tag 'documentable'
  tag legacy: ['SV-71161', 'V-56901']
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end
