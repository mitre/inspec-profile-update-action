control 'SV-203771' do
  title 'The operating system must generate audit records when concurrent logons to the same account occur from different sources.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system generates audit records when concurrent logons to the same account occur from different sources. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when concurrent logons to the same account occur from different sources.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3896r375704_chk'
  tag severity: 'medium'
  tag gid: 'V-203771'
  tag rid: 'SV-203771r381481_rule'
  tag stig_id: 'SRG-OS-000473-GPOS-00218'
  tag gtitle: 'SRG-OS-000473'
  tag fix_id: 'F-3896r375705_fix'
  tag 'documentable'
  tag legacy: ['V-56611', 'SV-70871']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
