control 'SV-224081' do
  title 'IBM z/OS UNIX MVS data sets used as step libraries in /etc/steplib must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to the pathname from the STEPLIBLIST line in BPXPRMxx member of PARMLIB.
From the ISPF Command shell enter:
ISHELL

on the command line:
on the path name line enter:
/etc/ 

From the resulting display scroll down to the <stepliblist name> from BPXPRMxx parm.

Enter B for browse on that line.

If ESM data set rules for libraries specified restrict WRITE or greater access to only systems programming personnel, this is not a finding.

If the ESM data set rules for libraries specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is not a finding.'
  desc 'fix', 'Configure the WRITE or greater access to libraries residing in the /etc/steplib to be limited to system programmers only.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25754r516642_chk'
  tag severity: 'medium'
  tag gid: 'V-224081'
  tag rid: 'SV-224081r877919_rule'
  tag stig_id: 'TSS0-US-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25742r516643_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107973', 'V-98869']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
