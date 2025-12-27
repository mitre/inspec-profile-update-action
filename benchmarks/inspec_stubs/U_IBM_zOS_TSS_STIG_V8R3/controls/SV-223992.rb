control 'SV-223992' do
  title 'IBM z/OS JESNEWS resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOHAS OPERCMDS(JES2.)
NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem. 

If access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class restricts CONTROL access to the appropriate personnel (i.e., users responsible for maintaining the JES News data set) and all access is logged, this is not a finding.'
  desc 'fix', 'Configure access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class to restrict CONTROL access to the appropriate personnel (i.e., users responsible for maintaining the JES News data set) and all access is logged. 

NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem. 

For Example:

The following command example may be used to allow all valid TOP SECRET users read access to the JES News data set:

TSS PERMIT(ALL) JESSPOOL(localnodeid.jesid.$JESNEWS.*.*.JESNEWS) –
ACCESS(READ)

The following is a sample command to allow production control personnel with a profile ACID of prodacid to update the JES News data set:

TSS PERMIT(prodacid) OPERCMDS(JES2.UPDATE.JESNEWS) -
ACCESS(CONTROL) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25665r516375_chk'
  tag severity: 'medium'
  tag gid: 'V-223992'
  tag rid: 'SV-223992r561402_rule'
  tag stig_id: 'TSS0-JS-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25653r516376_fix'
  tag 'documentable'
  tag legacy: ['SV-107795', 'V-98691']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
