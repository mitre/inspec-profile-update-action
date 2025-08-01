control 'SV-224080' do
  title 'IBM z/OS UNIX MVS data sets with z/OS UNIX components must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'If the ESM data set rules for each of the data sets listed in the table below restrict WRITE or greater access to systems programming personnel, this is not a finding.

MVS DATA SETS WITH z/OS UNIX COMPONENTS
DATA SET NAME/MASK MAINTENANCE TYPE FUNCTION
SYS1.ABPX* Distribution IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.AFOM* Distribution IBM z/OS UNIX Application Services
SYS1.BPA.ABPA* Distribution IBM z/OS UNIX Connection Scaling Process Mgr.
SYS1.CMX.ACMX* Distribution IBM z/OS UNIX Connection Scaling Connection Mgr.
SYS1.SBPX* Target IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.SFOM* Target IBM z/OS UNIX Application Services
SYS1.CMX.SCMX* Target IBM z/OS UNIX Connection Scaling Connection Mgr.'
  desc 'fix', "Define ESM data set rules for each of the data sets listed in the table below; restrict WRITE or greater access to systems programming personnel.

MVS DATA SETS WITH z/OS UNIX COMPONENTS
DATA SET NAME/MASK MAINTENANCE TYPE FUNCTION
SYS1.ABPX* Distribution IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.AFOM* Distribution IBM z/OS UNIX Application Services
SYS1.BPA.ABPA* Distribution IBM z/OS UNIX Connection Scaling Process Mgr.
SYS1.CMX.ACMX* Distribution IBM z/OS UNIX Connection Scaling Connection Mgr.
SYS1.SBPX* Target IBM z/OS UNIX ISPF panels, messages, tables, clists
SYS1.SFOM* Target IBM z/OS UNIX Application Services
SYS1.CMX.SCMX* Target IBM z/OS UNIX Connection Scaling Connection Mgr.

The data sets designated as distribution data sets should have all access restricted to systems programming personnel. TSO/E users who also use z/OS UNIX should have read access to the SYS1.SBPX* data sets. Read access for all users to the remaining target data sets is at the site's discretion. All other access must be restricted to systems programming personnel."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25753r516639_chk'
  tag severity: 'medium'
  tag gid: 'V-224080'
  tag rid: 'SV-224080r869020_rule'
  tag stig_id: 'TSS0-US-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25741r869019_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['SV-107971', 'V-98867']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
