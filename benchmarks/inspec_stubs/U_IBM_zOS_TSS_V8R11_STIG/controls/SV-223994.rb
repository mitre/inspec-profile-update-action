control 'SV-223994' do
  title 'IBM z/OS JES2 spool resources must be controlled in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOHAS JESSPOOL(localnodeid.)

If the following guidance is true, this is not a finding.

Review the JESSPOOL report for resource permissions with the following naming convention. These permissions may be fully qualified, be specified as generic, or be specified with masking as indicated below:

localnodeid.useracid.jobname.jobid.dsnumber.name

localnodeid - The name of the node on which the SYSIN or SYSOUT data set currently resides.
useracid - The user ACID associated with the job. This is the user ACID TSS uses for validation purposes when the job runs.
jobname - The name that appears in the name field of the JOB statement.
jobid - The job number JES2 assigned to the job.
dsnumber - The unique data set number JES2 assigned to the spool data set. A D is the first character of this qualifier.
name - The name of the data set specified in the DSN= parameter of the DD statement. If the JCL did not specify DSN= on the DD statement that creates the spool data set, JES2 uses a question mark (?).

All users must have access to their own JESSPOOL resources. Permission can be granted by resource permission JESSPOOL(localnodeid.%.) ACCESS(ALL). This permission can be given to profiles, individual user, and/or the ALL record. Access to this resource does not require logging.

Ensure the following items are in effect:

The localnodeid. resource will be restricted to only system programmers, operators, and automated operations personnel, with access of ALL. All access will be logged. (localnodeid. resource includes all generic and/or masked permissions, example: localnodeid.**, localnodeid.*, etc.)

The JESSPOOL localnodeid.userid.jobname.jobid.dsnumber.name, whether generic and/or masked, can be made available to users, when approved by the ISSO. Access will be identified at the minimum access for the user to accomplish the users function. All access will be logged. An example is team members within a team, providing the capability to view, help, and/or debug other team member jobs/processes.

CSSMTP will be restricted to localnodeid.userid.jobname.jobid.dsnumber.name, whether generic and/or masked when approved by the ISSO. All access will be logged.

Spooling products users (CA-SPOOL, CA View, etc.) will be restricted to localnodeid.userid.jobname.jobid.dsnumber.name, whether generic and/or masked when approved by the ISSO. Logging of access is not required.'
  desc 'fix', %q(Configure the following items to be in effect for JESSPOOL resources. The JESSPOOL may have more restrictive security at the direction of the ISSO.

The JESSPOOL resources may be fully qualified, be specified as generic, or be specified with masking as indicated below:

localnodeid.userid.jobname.jobid.dsnumber.name

localnodeid - The name of the node on which the SYSIN or SYSOUT data set currently resides.
userid - The userid associated with the job. This is the userid used for validation purposes when the job runs.
jobname - The name that appears in the name field of the JOB statement.
jobid - The job number JES2 assigned to the job.
dsnumber - The unique data set number JES2 assigned to the spool data set. A D is the first character of this qualifier.
name - The name of the data set specified in the DSN= parameter of the DD statement. If the JCL did not specify DSN= on the DD statement that creates the spool data set, JES2 uses a question mark (?).

All users must have access to their own JESSPOOL resources. Permission can be granted by resource permission JESSPOOL(localnodeid.%.) ACCESS(ALL). This permission can be given to profiles, individual user, and/or the ALL record. Access to this resource does not require logging.

Example:
TSS ADDTO(deptacid) JESSPOOL(localnode.)
TSS PERMIT(ALL) JESSPOOL(localnode.%.) ACCESS(ALL)

The localnodeid. resource will be restricted to only system programmers, operators, and automated operations personnel, with access of ALL. All access will be logged. (localnodeid. resource includes all generic and/or masked permissions, example: localnodeid.**, localnodeid.*, etc.)

Example:
TSS PERMIT(syspsmpl) JESSPOOL(localnodeid.) ACCESS(ALL) ACTION(AUDIT)

The JESSPOOL localnodeid.userid.jobname.jobid.dsnumber.name, whether generic and/or masked, can be made available to users, when approved by the ISSO. Access will be identified at the minimum access for the user to accomplish the users function. All access will be logged. An example is team members within a team, providing the capability to view, help, and/or debug other team member jobs/processes. If frequent situations occur where users working on a common project require selective access to each other's jobs, then the installation may delegate to the individual users the authority to grant access, but only with the approval of the ISSO.

Example:
TSS PERMIT(Project1-profile) JESSPOOL(localnodeid.UMO) ACCESS(ALL)

If IBM's SDSF product is installed on the system, resources defined to the JESSPOOL resource class control functions related to jobs, output groups, and SYSIN/SYSOUT data sets on various SDSF panels.

CSSMTP will not be granted to the JESSPOOL resource of the high level "node." or "localnodeid.". CSSMTP can have access to the specific approved JESSPOOL resources, minimally qualified to the "node.userid." and all access will be logged. This will ensure system records who (userid) sent traffic to CSSMTP, when and what job/process.

Spooling products users (CA-SPOOL, CA View, etc.) will be restricted to localnodeid.userid.jobname.jobid.dsnumber.name, whether generic and/or masked when approved by the ISSO. Logging of access is not required.

The ISSO will review JESSPOOL resource rules. If a rule has been determined not to have been used within the last two years, the rule will be removed.)
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25667r516381_chk'
  tag severity: 'medium'
  tag gid: 'V-223994'
  tag rid: 'SV-223994r877835_rule'
  tag stig_id: 'TSS0-JS-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25655r868979_fix'
  tag 'documentable'
  tag legacy: ['SV-107799', 'V-98695']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
