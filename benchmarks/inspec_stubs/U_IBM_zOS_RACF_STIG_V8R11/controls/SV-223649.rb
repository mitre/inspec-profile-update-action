control 'SV-223649' do
  title 'IBM RACF must limit Write or greater access to SYS1.NUCLEUS to system programmers only.'
  desc 'This data set contains a large portion of the system initialization (IPL) programs and pointers to the master and alternate master catalog. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

'
  desc 'check', 'Execute a dataset access list for SYS1.NUCLEUS.

If all of the Following are untrue, this is not a finding.

If any of the following is true, this is a finding.

-The ACP data set rules for SYS1.NUCLEUS do not restrict WRITE or greater access to only z/OS systems programming personnel.
-The ACP data set rules for SYS1.NUCLEUS do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect SYS1.NUCLEUS.

Configure the WRITE or greater access to SYS1.NUCLEUS to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25322r514636_chk'
  tag severity: 'high'
  tag gid: 'V-223649'
  tag rid: 'SV-223649r853567_rule'
  tag stig_id: 'RACF-ES-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25310r514637_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98003', 'SV-107107']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
