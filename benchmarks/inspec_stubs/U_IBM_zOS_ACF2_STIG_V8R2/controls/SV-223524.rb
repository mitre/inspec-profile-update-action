control 'SV-223524' do
  title 'The IBM z/OS TFTP Server program must be properly protected.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From the ACF Command screen enter:
SET CONTROL(GSO)
LIST LIKE(PPGM-)

If Programs TFTPD and EZATD are not defined in the GSO PPGM record, this is a finding.

From the ACF Command screen enter:
SET RESOURCE(PGM)
LIST LIKE(-)

If Program resources TFTPD and EZATD are not defined in the PROGRAM resource class, this is a finding.

If No access to the program resources TFTPD and EZATD is permitted, this is not a finding.'
  desc 'fix', "Configure the resource controls for the TFTP Server programs TFTPD and EZATD and ensure all access is restricted.

Evaluate the impact of implementing the following change. Develop a plan of action and implement the change as required.

Configure the resource controls for the TFTP Server programs TFTPD and EZATD and ensure all access is restricted.

Examples:
SET CONTROL(GSO)
CHANGE PPGM PGM-MASK(TFTPD EZATD) ADD

F ACF2,REFRESH(PPGM)

$KEY(TFTPD) TYPE(PGM)
UID(*) PREVENT 

SET R(PGM)
COMPILE 'ACF2.MVA.PGM(TFTPD)' STORE

F ACF2,REBUILD(PGM) 

$KEY(EZATD) TYPE(PGM)
UID(*) PREVENT 

SET R(PGM)
COMPILE 'ACF2.MVA.PGM(EZATD)' STORE

F ACF2,REBUILD(PGM)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25197r504630_chk'
  tag severity: 'medium'
  tag gid: 'V-223524'
  tag rid: 'SV-223524r533198_rule'
  tag stig_id: 'ACF2-FT-000080'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25185r504631_fix'
  tag 'documentable'
  tag legacy: ['SV-106857', 'V-97753']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
