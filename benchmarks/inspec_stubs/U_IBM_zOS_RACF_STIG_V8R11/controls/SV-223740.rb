control 'SV-223740' do
  title 'The IBM z/OS TFTP server program must be properly protected.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From the ISPF Command Shell enter:
RL Program *

If Program resources TFTPD and EZATD are defined to the PROGRAM resource class with a UACC(NONE), this is not a finding. 

The library name where these programs are located is SYS1.TCPIP.SEZALOAD.

If no access to the program resources TFTPD and EZATD is permitted, this is not a finding.'
  desc 'fix', "Evaluate the impact of implementing the following change. Develop a plan of action and implement the change as required.

Define the EZATD program and its alias TFTPD to RACF with no access granted. The following commands provide a sample of how this can be accomplished.

rdef program tftpd addmem('sys1.tcpip.sezaload'//nopadchk) -
data('Reference SRR PDI # IFTP0090') - 
audit(all(read)) UACC(none) owner(admin) 

rdef program ezatd -
addmem('sys1.tcpip.sezaload'//nopadchk) -
data('Reference SRR PDI # IFTP0090') - 
audit(all(read)) UACC(none) owner(admin) 

A PROGRAM class refresh will be necessary and can be accomplished with the command:

setr when(program) refresh"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25413r514908_chk'
  tag severity: 'medium'
  tag gid: 'V-223740'
  tag rid: 'SV-223740r853607_rule'
  tag stig_id: 'RACF-FT-000080'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25401r767084_fix'
  tag 'documentable'
  tag legacy: ['V-98187', 'SV-107291']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
