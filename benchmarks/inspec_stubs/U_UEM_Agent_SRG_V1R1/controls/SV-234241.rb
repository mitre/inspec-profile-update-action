control 'SV-234241' do
  title 'The UEM Agent must queue alerts if the trusted channel is not available.'
  desc 'Alerts providing notification of a change in enrollment state facilitate verification of the correct operation of security functions. When an UEM server receives such an alert from an UEM Agent, it indicates the security policy may no longer be enforced on the mobile device. This enables the UEM administrator to take an appropriate remedial action.

'
  desc 'check', 'Verify the UEM Agent queues alerts if the trusted channel is not available.

If the UEM Agent does not queue alerts if the trusted channel is not available, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to queue alerts if the trusted channel is not available.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37426r612029_chk'
  tag severity: 'medium'
  tag gid: 'V-234241'
  tag rid: 'SV-234241r617354_rule'
  tag stig_id: 'SRG-APP-000358-UEM-100003'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-37391r612030_fix'
  tag satisfies: ['FAU_ALT_EXT.2.2']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
