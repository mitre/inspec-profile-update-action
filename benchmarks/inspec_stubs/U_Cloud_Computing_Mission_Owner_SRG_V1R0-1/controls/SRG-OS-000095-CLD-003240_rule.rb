control 'SRG-OS-000095-CLD-003240_rule' do
  title 'The Mission Owner of the IaaS or PaaS must remove all upgraded or replaced software and firmware components that are no longer required for operation.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'If this is a SaaS, this is not a finding.

If the Mission Owner of the IaaS or PaaS has not removed all upgraded or replaced software and firmware components that are no longer required for operation, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Remove all upgraded or replaced software and firmware components that are no longer required for operation from the IaaS/PaaS.'
  impact 0.5
  tag check_id: 'C-SRG-OS-000095-CLD-003240_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000095-CLD-003240'
  tag rid: 'SRG-OS-000095-CLD-003240_rule'
  tag stig_id: 'SRG-OS-000095-CLD-003240'
  tag gtitle: 'SRG-OS-000095-CLD-003240'
  tag fix_id: 'F-SRG-OS-000095-CLD-003240_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
