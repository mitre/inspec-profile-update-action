control 'SV-90787' do
  title 'The OS X system must employ automated mechanisms to determine the state of system components with regard to flaw remediation using the following frequency: continuously where HBSS is used; 30 days for any additional internal network scans not covered by HBSS; and annually for external scans by Computer Network Defense Service Provider (CNDSP).'
  desc 'An approved tool for continuous network scanning must be installed and configured to run.

Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the operating system or other system components may remain vulnerable to the exploits presented by undetected software flaws.

To support this requirement, the operating system may have an integrated solution incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified in the requirement.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved tool capable of continuous scanning is loaded on the system. The recommended system is the McAfee HBSS.

If no such tool is installed on the system, this is a finding.'
  desc 'fix', 'Install an approved HBSS solution onto the system.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76099'
  tag rid: 'SV-90787r1_rule'
  tag stig_id: 'AOSX-12-000835'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-82737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
