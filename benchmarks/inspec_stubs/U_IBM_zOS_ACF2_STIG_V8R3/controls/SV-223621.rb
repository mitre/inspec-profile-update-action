control 'SV-223621' do
  title 'IBM z/OS BPX resource(s) must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET RESOURCE(FAC)
SET VERBOSE
LIST LIKE(BPX-)

If the ACF2 rules for the BPX resource specify a default access of NONE, this is not a finding.

If there are no ACF2 rules that allow access to the BPX resource, this is not a finding.

If there is no ACF2 rule for BPX.SAFFASTPATH defined, this is not a finding.

If the ACF2 rules for each of the BPX resources listed in z/OS UNIX System Services Planning, Establishing UNIX security, specify a default access of NONE, this is not a finding.

If the ACF2 rules for each of the BPX resources listed in the in z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel, this is not a finding.'
  desc 'fix', 'Configure BPX. Resources to be properly protected and access is restricted to appropriate system tasks or systems programming personnel.

Configure the following items for the FACILITY resource class, TYPE(FAC):

The ACF2 rules for the BPX resource specify a default access of NONE.

Example:
$KEY(BPX) TYPE(FAC)
- UID(*) PREVENT

There are no ACF2 rules that allow access to the BPX resource.

Example:
$KEY(BPX) TYPE(FAC)
- UID(*) PREVENT

There is no ACF2 rule for BPX.SAFFASTPATH defined.

Example:
$KEY(BPX) TYPE(FAC)
SAFFASTPATH UID(*) PREVENT

The ACF2 rules for each of the BPX resources listed in the General Facility Class BPX Resources Table, in the z/OS UNIX System Services Planning, Establishing UNIX security, specify a default access of NONE.

Example:
$KEY(BPX) TYPE(FAC)
DAEMON UID(*) PREVENT
DEBUG UID(*) PREVENT 
FILEATTR.APF UID(*) PREVENT
FILEATTR.PROGCTL UID(*) PREVENT
JOBNAME UID(*) PREVENT
SAFFASTPATH UID(*) PREVENT
SERVER UID(*) PREVENT
SMF UID(*) PREVENT
STOR.SWAP UID(*) PREVENT
SUPERUSER UID(*) PREVENT
WLMSERVER UID(*) PREVENT

The ACF2 rules for each of the BPX resources listed in the General Facility Class BPX Resources Table, in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel as specified.

Example:
$KEY(BPX) TYPE(FAC)
DAEMON UID(*******STC******FTPD) SERVICE(READ) LOG
DAEMON UID(*******STC******INETD) SERVICE(READ) LOG 
DAEMON UID(*******STC******NAMED) SERVICE(READ) LOG 
DAEMON UID(*******STC******OMVSKERN) SERVICE(READ) LOG
DAEMON UID(*******STC******OMVS) SERVICE(READ) LOG 
DAEMON UID(*******STC******OROUTED) SERVICE(READ) LOG 
DAEMON UID(*******STC******OSNMPD) SERVICE(READ) LOG'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25294r504821_chk'
  tag severity: 'medium'
  tag gid: 'V-223621'
  tag rid: 'SV-223621r533198_rule'
  tag stig_id: 'ACF2-US-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25282r504822_fix'
  tag 'documentable'
  tag legacy: ['V-97947', 'SV-107051']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
