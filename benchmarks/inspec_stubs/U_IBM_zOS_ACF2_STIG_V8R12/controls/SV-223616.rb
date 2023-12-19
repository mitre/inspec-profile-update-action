control 'SV-223616' do
  title 'IBM z/OS UNIX SUPERUSER resource must be protected in accordance with guidelines.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
RESOURCE(UNI)
LIST LIKE(SUPER-)

If the ACF2 rules for the SUPERUSER resource specify a default access of NONE, this is not a finding.

If there are no ACF2 rules that allow access to the SUPERUSER resource, this is not a finding.

If there is no ACF2 rule for CHOWN.UNRESTRICTED defined, this is not a finding.

If the ACF2 rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX Security, specify a default access of NONE, this is not a finding.

If the ACF2 rules for each of the SUPERUSER resources listed in the UNIXPRIV CLASS RESOURCES Table in the z/OS UNIX System Services Planning, Establishing UNIX Security, restrict access to appropriate system tasks or systems programming personnel, this is not a finding.'
  desc 'fix', 'Configure ACF2 SUPERUSER resources for the UNIXPRIV resource class to restrict to appropriate system tasks and/or system programming personnel.

Configure the ACF2 rules for the SUPERUSER resource to specify a default access of NONE.

Configure no ACF2 rules that allow access to the SUPERUSER resource.

Configure no ACF2 rule for CHOWN.UNRESTRICTED defined.

Configure the ACF2 rules for each of the SUPERUSER resources listed in the UNIXPRIV CLASS RESOURCES Table in the z/OS UNIX System Services Planning, Establishing UNIX security to specify a default access of NONE.

Configure the ACF2 rules for each of the SUPERUSER resources listed in the UNIXPRIV CLASS RESOURCES Table in the z/OS UNIX System Services Planning, Establishing UNIX security to restrict access to appropriate system tasks or systems programming personnel.

Example:
SET R(UNI)
$KEY(SUPERUSER) TYPE(UNI) 
$MEMBER(SUPRUSER)
FILESYS UID(sysprgmr LOG 
FILESYS.CHOWN UID(sysprgmr) LOG 
FILESYS.MOUNT UID(sysprog) LOG 
FILESYS.PFSCTL UID(sysprgmr) LOG 
FILESYS.VREGISTER UID(sysprgmr) LOG 
IPC.RMID UID(sysprgmr) LOG 
PROCESS.GETPSENT UID(sysprgmr) LOG 
PROCESS.KILL UID(sysprgmr) LOG 
PROCESS.PTRACE UID(sysprgmr) LOG 
SETPRIORITY UID(sysprgmr) LOG 
- UID(*) PREVENT'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25289r504809_chk'
  tag severity: 'high'
  tag gid: 'V-223616'
  tag rid: 'SV-223616r533198_rule'
  tag stig_id: 'ACF2-US-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25277r504810_fix'
  tag 'documentable'
  tag legacy: ['SV-107041', 'V-97937']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
