control 'SV-214891' do
  title 'The macOS system must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously where HBSS is used; 30 days for any additional internal network scans not covered by HBSS; and annually for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'An approved tool for continuous network scanning must be installed and configured to run.

Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved tool capable of continuous scanning is loaded on the system. The recommended system is the McAfee HBSS.

If no such tool is installed on the system, this is a finding.'
  desc 'fix', 'Install an approved HBSS solution onto the system.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16091r466228_chk'
  tag severity: 'medium'
  tag gid: 'V-214891'
  tag rid: 'SV-214891r609363_rule'
  tag stig_id: 'AOSX-13-000835'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-16089r466229_fix'
  tag 'documentable'
  tag legacy: ['V-81661', 'SV-96375']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
