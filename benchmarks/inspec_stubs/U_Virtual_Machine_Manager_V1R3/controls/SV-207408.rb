control 'SV-207408' do
  title 'The VMM must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the VMM or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the VMM may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify the VMM employs automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not covered by HBSS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7665r365634_chk'
  tag severity: 'medium'
  tag gid: 'V-207408'
  tag rid: 'SV-207408r878139_rule'
  tag stig_id: 'SRG-OS-000191-VMM-000730'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-7665r365635_fix'
  tag 'documentable'
  tag legacy: ['V-57017', 'SV-71277']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
