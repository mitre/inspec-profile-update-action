control 'SV-223928' do
  title 'Data set masking characters allowing access to all data sets must be properly restricted in the CA-TSS security database.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer the accesses to the TSS masking character (*, *., and/or **) for data sets. 

If the following guidance is true, this is not a finding.

If the TSS data set access authorizations restrict READ access to auditors, this is not a finding.

If the TSS data set access authorizations restrict READ and/or greater access to DASD administrators, Trusted Started Tasks, emergency users, and DASD batch users, this is not a finding.

If CA VTAPE is installed on the systems and the TSS data set access authorizations restrict READ access to CA VTAPE STCs and/or batch users, this is not a finding.

If the TSS data set access authorizations specify that all (i.e., failures and successes) EXECUTE and/or greater accesses are logged, this is not a finding.'
  desc 'fix', "Review access authorization to the TSS mask character (*, *., and/or **) for data sets. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to restrict access to the data set mask permissions.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater accesses are logged. The programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented, will work with the ISSO to confirm that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Auditors may require READ access to all data sets.
DASD administrators, Trusted Started Tasks, emergency users, and DASD batch users that require READ and/or greater access to perform maintenance to all data sets.
If CA VTAPE is installed on the system, READ access can be given to the CA VTAPE STCs and/or batch users.
All accesses authorizations will be logged. The exception is the logging requirement is not required for Trusted Started Tasks.

The following commands are provided as a sample for implementing data set controls:

TSS ADDTO(msca) DATASET(*.)
TSS PERMIT(smplsmpl) DATASET(*.) ACCESS(READ) ACTION(AUDIT)
TSS PERMIT(CA VTape STC) DATASET(*.) ACCESS(READ) ACTION(AUDIT)
TSS PERMIT(dasbsmpl) DATASET(*.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(dasdsmpl) DATASET(*.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(emersmpl) DATASET(*.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(tstcsmpl) DATASET(*.) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25601r868950_chk'
  tag severity: 'medium'
  tag gid: 'V-223928'
  tag rid: 'SV-223928r868952_rule'
  tag stig_id: 'TSS0-ES-000550'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25589r868951_fix'
  tag 'documentable'
  tag legacy: ['V-98563', 'SV-107667']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
