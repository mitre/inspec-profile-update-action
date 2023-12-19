control 'SV-224076' do
  title 'IBM z/OS BPX resource(s) must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS IBMFAC(BPX.)

If the BPX. resource is properly owned, this is not a finding.

From the ISPF Command Shell enter:
TSS WHOHAS (<each BPX resource>)

If any item below are untrue, this is a finding.

-There are no TSS rules that allow access to the BPX resource.
-There are no TSS rules for BPX.SAFFASTPATH defined.
-The TSS rules for each of the BPX resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel.'
  desc 'fix', 'Because they convey especially powerful privileges, the settings for BPX.DAEMON, BPX.SAFFASTPATH, BPX.SERVER, and BPX.SUPERUSER require special attention. 

Review the following items for the IBMFAC resource class: 

-The TSS owner defined for the BPX resource. 
-There are no TSS rules that allow access to the BPX resource. 
-There are no TSS rules for BPX.SAFFASTPATH defined. 

The TSS rules for each of the BPX resources listed in General Facility Class BPX Resources Table, in the z/OS UNIX System Services Planning, Establishing UNIX security restrict access to appropriate system tasks or systems programming personnel. Access can be permitted only to users with a requirement for the resource that is documented to the ISSO. Access to BPX.DAEMON must be restricted to the z/OS UNIX kernel userid, z/OS UNIX daemons (e.g., inetd, syslogd, ftpd), and other system software daemons (e.g., web servers). When BPX.SAFFASTPATH is defined, calls to the ACP are not performed for file accesses and there is no audit trail of access failures. This configuration is unacceptable. Therefore BPX.SAFFASTPATH must not be used on any system. 

For Example:
The following commands can be used to provide the required protection:

TSS ADD(ADMIN) IBMFAC(BPX.)
TSS PERMIT(ALL) IBMFAC(BPX.SAFFASTPATH) ACCESS(NONE)

NOTE:
The PERMIT command for BPX.SAFFASTPATH must be executed on TOP SECRET systems. If access to BPX.SAFFSTPATH were allowed, z/OS UNIX would perform permission bit checking internally instead of calling the ACP. On TOP SECRET systems this would bypass any audit trail of violations. In addition, the z/OS UNIX kernel userid (OMVS is the example in this section) must not have the TOP SECRET NORESCHK privilege. Having that privilege would allow access to BPX.SAFFASTPATH even though the access restriction was in place.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25749r516627_chk'
  tag severity: 'medium'
  tag gid: 'V-224076'
  tag rid: 'SV-224076r695474_rule'
  tag stig_id: 'TSS0-US-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25737r516628_fix'
  tag 'documentable'
  tag legacy: ['SV-107963', 'V-98859']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
