control 'SV-223995' do
  title 'IBM z/OS JES2 system commands must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOHAS OPERCMDS(JES2.)

If the JES2.** resource is defined to the OPERCMDS class with an access of NONE and all access is logged, this is not a finding.

If access to JES2 system commands defined in the IBM z/OS JES2 commands is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users), this is not a finding.

NOTE: Use the GROUP category specified in the table referenced above as a guideline to determine appropriate personnel access to system commands.'
  desc 'fix', "Extended MCS support allows the installation to control the use of JES2 system commands through the ESM. These commands are subject to various types of potential abuse. For this reason, it is necessary to place restrictions on the JES2 system commands that can be entered by particular operators.

Some commands are particularly dangerous and should only be used when less drastic options have been exhausted. Misuse of these commands can create a situation in which the only recovery is an IPL.

To control access to JES2 system commands, apply the following:
implementing security:

Define the JES2.** resource in the OPERCMDS class with an access of NONE and all access is logged.

Define the JES2 system commands as specified in the IBM z/OS JES2 Commands to be restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users), as determined in the documented site Security Plan.

Define the JES2 system commands with proper logging as determined in the documented site Security Plan.
Note: Display commands and others as deemed by the site IAW site security plan may be allowed for all users with no logging. 

Build a command file based on the referenced JES2 Command Table. A sample of the commands in the command file is provided here:

RDEF OPERCMDS JES2.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('REQUIRED BY SRR PDI ZJES0052')

RDEF OPERCMDS JES2.<command>.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('REQUIRED BY SRR PDI ZJES0052')
PE JES2.<command>.** CL(OPERCMDS) ID(<syspsmpl>) ACC(U)

SETR RACL(OPERCMDS) REF"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25668r516384_chk'
  tag severity: 'medium'
  tag gid: 'V-223995'
  tag rid: 'SV-223995r561402_rule'
  tag stig_id: 'TSS0-JS-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25656r516385_fix'
  tag 'documentable'
  tag legacy: ['SV-107801', 'V-98697']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
