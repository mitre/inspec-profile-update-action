control 'SV-223454' do
  title 'CA-ACF2 Access to SYS1.LINKLIB must be properly protected.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

The operating system or software configuration management utility must enforce control of software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization.

'
  desc 'check', 'Execute a data set list of access to SYS1.LINKLIB.

If the ESM data set rules for SYS1.LINKLIB allow inappropriate (e.g., global READ) access, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ, UPDATE and ALTER access to only systems programming personnel, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.LINKLIB do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged this is a finding.'
  desc 'fix', 'Configure the ESM rules for SYS1.LINKLIB limit access to system programmers only and all update and allocate access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25127r504494_chk'
  tag severity: 'medium'
  tag gid: 'V-223454'
  tag rid: 'SV-223454r533198_rule'
  tag stig_id: 'ACF2-ES-000330'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25115r504495_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000362-GPOS-00149']
  tag 'documentable'
  tag legacy: ['V-97605', 'SV-106709']
  tag cci: ['CCI-001499', 'CCI-001812', 'CCI-000213', 'CCI-002235']
  tag nist: ['CM-5 (6)', 'CM-11 (2)', 'AC-3', 'AC-6 (10)']
end
