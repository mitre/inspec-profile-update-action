control 'SV-203662' do
  title 'The operating system must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where Endpoint Security Solution (ESS) is used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using ESS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify the operating system employs automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where ESS is used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by CNDSP.

If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where ESS is used; 30 days, for any additional internal network scans not covered by ESS; and annually, for external scans by CNDSP.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3787r804661_chk'
  tag severity: 'medium'
  tag gid: 'V-203662'
  tag rid: 'SV-203662r804662_rule'
  tag stig_id: 'SRG-OS-000191-GPOS-00080'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-3787r804655_fix'
  tag 'documentable'
  tag legacy: ['V-56883', 'SV-71143']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
