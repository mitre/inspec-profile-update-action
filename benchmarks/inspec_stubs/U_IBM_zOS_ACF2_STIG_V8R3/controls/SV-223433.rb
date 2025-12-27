control 'SV-223433' do
  title 'CA-ACF2 must limit access to SYSTEM DUMP data sets to appropriate authorized users.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Ask the system administrator and/or DASD administrator to determine the System Dump data sets. 

Refer to data sets SYS1.DUMPxx, additionally, Dump data sets can be identified by reviewing the logical parmlib concatenation data sets for the current COMMNDxx member. Find the COM= which specifies the DUMPDS NAME (DD NAME=name-pattern) entry. The name-pattern is used to identify additional Dump data sets.

If ESM data set rules for System Dump data sets do not restrict READ, UPDATE, and/or ALTER access to only systems programming personnel, this is a finding.

If ESM data set rules for all System Dump data sets do not restrict READ access to personnel having justification to review these dump data, this is a finding.'
  desc 'fix', 'Configure data set rules for access to SYSTEM DUMP data set(s) to be limited to system programmers only, unless a letter justifying access is filed with the ISSO in the site security plan.

Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to restrict access to these data sets.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25106r504434_chk'
  tag severity: 'medium'
  tag gid: 'V-223433'
  tag rid: 'SV-223433r533198_rule'
  tag stig_id: 'ACF2-ES-000120'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25094r504435_fix'
  tag 'documentable'
  tag legacy: ['V-97563', 'SV-106667']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
