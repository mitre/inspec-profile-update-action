control 'SV-223466' do
  title 'CA-ACF2 must limit Write or greater access to libraries that contain PPT modules to system programmers only.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

'
  desc 'check', "Review program entries in the IBM Program Properties Table (PPT). You may use a third-party product to examine these entries however, to determine program entries issue the following command from an ISPF command line:
TSO ISRDDN LOAD IEFSDPPT
Press Enter

For each module identified in the 'eyecatcher' : 

If all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

-The ESM data set rules for libraries that contain PPT modules do not restrict UPDATE and ALLOCATE access to only z/OS systems programming personnel.
-The ESM data set rules for libraries that contain PPT modules do not specify that all UPDATE and ALLOCATE access will be logged."
  desc 'fix', 'Configure the Update and Allocate access to libraries containing PPT modules to be limited to system programmers only and all Update and Allocate access is logged.'
  impact 0.3
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25139r504516_chk'
  tag severity: 'low'
  tag gid: 'V-223466'
  tag rid: 'SV-223466r853530_rule'
  tag stig_id: 'ACF2-ES-000480'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25127r504517_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97631', 'SV-106735']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
