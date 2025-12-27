control 'SV-223656' do
  title 'IBM RACF must properly define users that have access to the CONSOLE resource in the TSOAUTH resource class.'
  desc 'MCS consoles can be used to issue operator commands. Failure to properly control access to MCS consoles could result in unauthorized personnel issuing sensitive operator commands. This exposure may threaten the integrity and availability of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'If the CONSOLE privilege is not defined to the TSOAUTH resource class, this is not a finding.

At the discretion of the site, users may be allowed to issue z/OS system commands from a TSO session. With this in mind, review the following items for users granted the CONSOLE resource in the TSOAUTH resource class:

If Userids are restricted to the INFO level on the AUTH parameter specified in the OPERPARM segment of their userid, this is not a finding.

If Userids are restricted to READ access to the MVS.MCSOPER.userid resource defined in the OPERCMDS resource class, this is not a finding.

If Userids and/or group IDs are restricted to READ access to the CONSOLE resource defined in the TSOAUTH resource class, this is not a finding.'
  desc 'fix', 'Evaluate the impact of correcting any deficiencies. Develop a plan of action and implement the required changes. 
Ensure the following items are in effect for all MCS consoles:

Define a profile protecting the use of the CONSOLE command within TSO. A sample command to accomplish this is shown here: RDEF TSOAUTH CONSOLE UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) 

Permit only authorized users. A sample command to accomplish this is shown here: PE CONSOLE CL(TSOAUTH) ID(<syspsmpl>)

Set up the OPERPARM segment in corresponding user-class entry. A sample command to accomplish this is shown here: ALU <authorized user> OPERPARM(AUTH(INFO))

Userids are restricted to READ access to the MVS.MCSOPER.userid resource defined in the OPERCMDS resource class. A sample command to accomplish this is shown here using the GLOBAL class: 
RDEF GLOBAL OPERCMDS ADDMEM(MVS.MCSOPER.&RACUID/READ) OWNER(ADMIN)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25329r514657_chk'
  tag severity: 'medium'
  tag gid: 'V-223656'
  tag rid: 'SV-223656r604139_rule'
  tag stig_id: 'RACF-ES-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25317r514658_fix'
  tag 'documentable'
  tag legacy: ['V-98017', 'SV-107121']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
