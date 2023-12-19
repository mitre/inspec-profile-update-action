control 'SV-223984' do
  title 'The IBM z/OS TFTP server program must be properly protected.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS PROGRAM(*) 

If the Program resources TFTPD and EZATD are owned appropriately in the PROGRAM resource class, this is not a finding.

Enter
TSS WHOHAS(TFTPD)
TSS WHOHAS(EZATD)

If no access to the program resources TFTPD and EZATD is permitted, this is not a finding.'
  desc 'fix', 'Evaluate the impact of implementing the following change. Develop a plan of action and implement the change as required. Ensure that the EZATD program and its alias TFTPD are defined to CA-TSS and no access to the program resources TFTPD and EZATD is permitted. The following commands provide a sample of how to protect the TFTP server program by assigning ownership and no permissions: TSS ADD(ADMIN) PROGRAM(TFTPD,EZATD)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25657r516351_chk'
  tag severity: 'medium'
  tag gid: 'V-223984'
  tag rid: 'SV-223984r856111_rule'
  tag stig_id: 'TSS0-FT-000120'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25645r516352_fix'
  tag 'documentable'
  tag legacy: ['V-98675', 'SV-107779']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
