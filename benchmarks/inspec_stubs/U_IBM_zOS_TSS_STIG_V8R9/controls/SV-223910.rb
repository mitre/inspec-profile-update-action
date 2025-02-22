control 'SV-223910' do
  title 'CA-TSS must limit access to SYSTEM DUMP data sets to system programmers only.'
  desc 'System DUMP data sets are used to record system data areas and virtual storage associated with system task failures. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

'
  desc 'check', 'Refer to data sets SYS1.DUMPxx, additionally, Dump data sets can be identified by reviewing the logical parmlib concatenation data sets for the current COMMNDxx member. Find the COM= which specifies the DUMPDS NAME (DD NAME=name-pattern) entry. The name-pattern is used to identify additional Dump data sets.

If the ESM data set rules for System Dump data sets do not restrict READ, UPDATE, and/or ALTER access to only systems programming personnel, this is a finding.

If the ESM data set rules for all System Dump data sets do not restrict READ access to personnel having justification to review these dump data sets, this is a finding.'
  desc 'fix', 'Configure data set rules for access to SYSTEM DUMP data set(s) to be limited to system programmers only, unless a letter justifying access is filed with the ISSO in the site security plan.

Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to restrict access to these data sets.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25583r516129_chk'
  tag severity: 'medium'
  tag gid: 'V-223910'
  tag rid: 'SV-223910r877751_rule'
  tag stig_id: 'TSS0-ES-000370'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25571r516130_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107631', 'V-98527']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
