control 'SV-223732' do
  title 'IBM RACF DASD Management USERIDs must be properly controlled.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'This applies to non-SMS volumes. For SMS-Managed volumes this is Not Applicable.

Ask the system administrator for all documents and procedures that apply to Storage Management, including identification of the DASD backup data sets and associated storage management userids.

From the ISPF Command enter:
RL User for each identified Userid.

Review storage management userids, if the following guidance is true, this is not a finding.

Storage management userids will not be given the "OPERATIONS" attribute.

Storage management userids will be defined with the "PROTECTED" attribute.

Storage management userids are permitted to the appropriate "STGADMIN" profiles in the "FACILITY" class for SMS-managed volumes.

Storage management userids assigned to storage management tasks (e.g., volume backup, data set archive and restore, etc.) are given access to data sets using "DASDVOL" and/or "GDASDVOL" profiles for non-SMS-managed volumes.

NOTE: "DASDVOL" profiles will not work with SMS-managed volume. "FACILITY" class profiles must be used instead. If "DFSMS/MVS" is used to perform DASD management operations, "FACILITY" class profiles may also be used to authorize storage management operations to non-SMS-managed volumes in lieu of using "DASDVOL" profiles. Therefore, not all volumes may be defined to the "DASDVOL/GDASDVOL" resource classes, and not all storage management userids may be represented in the profile access lists.'
  desc 'fix', 'Note: This applies to non-SMS volumes. Refer to the System Managed Storage group (i.e., ZSMSnnnn) for requirements for System managed Storage.
Evaluate the impact of accomplishing the change. Develop a plan of action and implement the change as required.

Ensure that storage management userids do not possess the "OPERATIONS" attribute. A sample command to accomplish this is shown here: 

ALU <userid> NOOPERATIONS

Ensure that storage management userids possess the "PROTECTED" attribute. A sample command to accomplish this is shown here: 

ALU <userid> NOPASS NOOIDCARD

Ensure that storage management userids are permitted to the appropriate "STGADMIN" profiles in the "FACILITY" class for SMS-managed volumes.

Ensure that storage management userids are permitted to appropriate "DASDVOL" profiles for non-SMS-managed volumes.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25405r514884_chk'
  tag severity: 'medium'
  tag gid: 'V-223732'
  tag rid: 'SV-223732r604139_rule'
  tag stig_id: 'RACF-ES-000850'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25393r514885_fix'
  tag 'documentable'
  tag legacy: ['V-98171', 'SV-107275']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
