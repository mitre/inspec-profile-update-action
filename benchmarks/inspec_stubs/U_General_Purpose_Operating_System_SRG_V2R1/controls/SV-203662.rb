control 'SV-203662' do
  title 'The operating system must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not cover'
  desc 'Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Verify the operating system employs automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans not co'
  desc 'fix', 'Configure the operating system to employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously, where HBSS is used; 30 days, for any additional internal network scans n'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3787r557231_chk'
  tag severity: 'medium'
  tag gid: 'V-203662'
  tag rid: 'SV-203662r557233_rule'
  tag stig_id: 'SRG-OS-000191-GPOS-00080'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-3787r557232_fix'
  tag 'documentable'
  tag legacy: ['V-56883', 'SV-71143']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
