control 'SV-223652' do
  title 'IBM RACF emergency USERIDs must be properly defined.'
  desc "Emergency accounts are privileged accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by the organization's system administrators when network or normal logon/access is not available). Infrequently used accounts are not subject to automatic termination dates. Emergency accounts are accounts created in response to crisis situations, usually for use by maintenance personnel. The automatic expiration or disabling time period may be extended as needed until the crisis is resolved; however, it must not be extended indefinitely. A permanent account should be established for privileged users who need long-term maintenance accounts.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements."
  desc 'check', 'Ask the system administrator for a list of all emergency userids available to the site along with the associated function of each userid.

Execute an access list for each emergency userid.

At a minimum an emergency logonid will exist with the security administration attributes specified in accordance with the following requirements. 

If the following guidance is not followed, this is a finding.

At least one userid exists to perform RACF security administration. These userids are defined to RACF with the system-SPECIAL attribute. They must not have the OPERATIONS attribute.

If any userids exist to perform operating system functions, they are defined without any RACF security administration privileges. These userids are defined to RACF with the system-OPERATIONS attribute, and FULL access to all DASD volumes. They must not have the SPECIAL attribute.

NOTE: A user who has the system-OPERATIONS attribute has FULL access authorization to all RACF-protected resources in the DASDVOL/GDASDVOL resource classes. However, if their userid or any associated group (i.e., default or connect) is in the access list of a resource profile, they will only have the access specified in the access list.

All emergency userids are defined to RACF and SYS1.UADS.

All emergency logonid/logonid(s) are to be implemented with logging to provide an audit trail of their activities. This is accomplished with the UAUDIT attribute.

All emergency logonid/logonid(s) will have distinct, different passwords in SYS1.UADS and in RACF, and the site is to establish procedures to ensure that the passwords differ. The password for any ID in SYS1.UADS is never to match the password for the same ID in RACF.

All emergency logonid/logonid(s) will have documented procedures to provide a mechanism for the use of the IDs. Their release for use is to be logged, and the log is to be maintained by the ISSO. When an emergency logonid is released for use, its password is to be reset by the ISSO within 12 hours.'
  desc 'fix', 'Configure emergency USERIDs to have access granted only authorizes those resources required to support the specific functions of either DASD Recovery or System Administration. 

Ensure the following items are in effect regarding emergency userids:

At a minimum an emergency userids will exists with the security administration attributes specified in accordance with the following requirements:

- Userids exist to perform RACF security administration only. These userids are defined to RACF with the system-SPECIAL attribute. They must not have the OPERATIONS attribute. Emergency userids will have either SPECIAL or OPERATIONS but not both.

- Userids can be defined to perform operating system functions. Such userids must be defined without any RACF security administration privileges. These userids are defined to RACF with the system-OPERATIONS attribute, FULL access to all DASD volumes resources as well as the FACILITY Class STGADMN profiles. They must not have the SPECIAL attribute.

NOTE: A user who has the system-OPERATIONS attribute has FULL access authorization to all RACF-protected resources in the DASDVOL/GDASDVOL resource classes. However, if their userid or any associated group (i.e., default or connect) is in the access list of a resource profile, they will only have the access specified in the access list since access lists override OPERATIONS.

- Userids exist to perform RACF security administration only. These userids are defined to RACF with the system-SPECIAL attribute. They must not have the OPERATIONS attribute. Emergency userids will have either SPECIAL or OPERATIONS but not both.

- All emergency userids are defined to RACF and SYS1.UADS. See TSO Command Ref for info on adding users to UADS.

- All emergency userids are to be implemented with logging to provide an audit trail of their activities. This is accomplished with the UAUDIT attribute via the command:

ALU <uid> UAUDIT

- All emergency userids will have distinct, different passwords in SYS1.UADS and in RACF, and the site is to establish procedures to ensure that the passwords differ. The password for any ID in SYS1.UADS is never to match the password for the same ID in RACF.

- All emergency userids will have documented procedures - such as a COOP Plan - to provide a mechanism for the use of the IDs. Their release for use is to be logged, and the log is to be maintained by the ISSO. When an emergency userids is released for use, its password is to be reset by the ISSO within 12 hours.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25325r514645_chk'
  tag severity: 'medium'
  tag gid: 'V-223652'
  tag rid: 'SV-223652r604139_rule'
  tag stig_id: 'RACF-ES-000040'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-25313r514646_fix'
  tag 'documentable'
  tag legacy: ['SV-107113', 'V-98009']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
