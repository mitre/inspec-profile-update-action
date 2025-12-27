control 'SV-223623' do
  title 'IBM z/OS UNIX MVS data sets with z/OS UNIX components must be properly protected.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'If the ESM data set rules for each of the data sets listed in the table below restrict UPDATE and ALLOCATE access to systems programming personnel, this is not a finding.

MVS DATA SETS WITH z/OS UNIX COMPONENTS
DATA SET NAME/MASK    MAINTENANCE TYPE    FUNCTION
SYS1.ABPX*            Distribution        IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.AFOM*            Distribution        IBM z/OS UNIX Application Services
SYS1.BPA.ABPA*        Distribution        IBM z/OS UNIX Connection Scaling Process Mgr.
SYS1.CMX.ACMX*        Distribution        IBM z/OS UNIX Connection Scaling Connection Mgr.
SYS1.SBPX*            Target              IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.SFOM*            Target              IBM z/OS UNIX Application Services
SYS1.CMX.SCMX*        Target              IBM z/OS UNIX Connection Scaling Connection Mgr.'
  desc 'fix', "Define ESM data set rules for each of the data sets listed in the table below restrict UPDATE and ALLOCATE access to systems programming personnel.

The data sets designated as distribution data sets should have all access restricted to systems programming personnel. TSO/E users who also use z/OS UNIX should have read access to the SYS1.SBPX* data sets. Read access for all users to the remaining target data sets is at the site's discretion. All other access must be restricted to systems programming personnel.

MVS DATA SETS WITH z/OS UNIX COMPONENTS
DATA SET NAME/MASK    MAINTENANCE TYPE    FUNCTION
SYS1.ABPX*            Distribution        IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.AFOM*            Distribution        IBM z/OS UNIX Application Services
SYS1.BPA.ABPA*        Distribution        IBM z/OS UNIX Connection Scaling Process Mgr.
SYS1.CMX.ACMX*        Distribution        IBM z/OS UNIX Connection Scaling Connection Mgr.
SYS1.SBPX*            Target              IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.SFOM*            Target              IBM z/OS UNIX Application Services
SYS1.CMX.SCMX*        Target              IBM z/OS UNIX Connection Scaling Connection Mgr."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25296r504827_chk'
  tag severity: 'medium'
  tag gid: 'V-223623'
  tag rid: 'SV-223623r533198_rule'
  tag stig_id: 'ACF2-US-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25284r504828_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-97951', 'SV-107055']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
