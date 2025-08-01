control 'SV-235033' do
  title 'IBM RACF must limit WRITE or greater access to LINKLIST libraries to system programmers only.'
  desc 'The primary function of the LINKLIST is to serve as a single repository for commonly used system modules. Failure to ensure that the proper set of libraries is designated for LINKLIST can impact system integrity, performance, and functionality. For this reason, controls must be employed to ensure that the correct set of LINKLIST libraries is used. Unauthorized access could result in the compromise of the operating system environment, ACP, and customer data.

'
  desc 'check', 'From Any ISPF input line, enter:
TSO ISRDDN LINKLIST

If all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

-The ACP data set rules for LINKLIST libraries do not restrict WRITE or greater access to only z/OS systems programming personnel.
-The ACP data set rules for LINKLIST libraries do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect the LINKLIST libraries.

Configure the WRITE or greater access to LINKLIST libraries to be limited to system programmers only and all WRITER or greater access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-38221r619947_chk'
  tag severity: 'medium'
  tag gid: 'V-235033'
  tag rid: 'SV-235033r853641_rule'
  tag stig_id: 'RACF-ES-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-38184r619948_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107111', 'V-98007']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
