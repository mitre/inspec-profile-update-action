control 'SV-223925' do
  title 'CA-TSS Emergency ACIDs must be properly limited and must audit all resource access.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the SYS1.UADS.

Ask the System Administrator for list of all emergency userids available to the site along with the associated function of each.

Note: If running Quest NC-Pass, validate that the Emergency ACIDS are identified to have the FACILITY of NCPASS and SECURID resource in the ABSTRACT resource class.

If these emergency ACID(s) have ability to ACCESS and UPDATE all system data sets, but do not have security administration privileges, this is not a finding.'
  desc 'fix', 'Configure any emergency ACID to have only access to resources required to support the specific functions of the owning department and that access to these resources is audited. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes.

TSS PER(acid) DSN(*****) ACCESS(ALL) ACTION(AUDIT)

Security Bypass Attributes NODSNCHK, NOVOLCHK, and NORESCHK will not be given to the Emergency ACIDs.

All emergency ACID(s) are to be implemented with logging to provide an audit trail of their activities.

All emergency ACID(s) are to be maintained in both the ACP and SYS1.UADS to ensure they are available in the event that the ACP is not functional.

All emergency ACID(s) will have distinct, different passwords in SYS1.UADS and in the ACP, and the site is to establish procedures to ensure that the passwords differ. The password for any ID in SYS1.UADS is never to match the password for the same ID in the ACP.

All emergency ACID(s) will have documented procedures to provide a mechanism for the use of the IDs. Their release for use is to be logged, and the log is to be maintained by the ISSO. When an emergency ACID is released for use, its password is to be reset by the ISSO within 12 hours.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25598r516174_chk'
  tag severity: 'high'
  tag gid: 'V-223925'
  tag rid: 'SV-223925r561402_rule'
  tag stig_id: 'TSS0-ES-000510'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25586r516175_fix'
  tag 'documentable'
  tag legacy: ['SV-107661', 'V-98557']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
