control 'SV-223716' do
  title 'IBM z/OS must properly protect MCS console userid(s).'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

MCS consoles can be used to issue operator commands. Failure to properly control access to MCS consoles could result in unauthorized personnel issuing sensitive operator commands. This exposure may threaten the integrity and availability of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to IEASYS00 to determine correct CONSOLxx member. 

Examine the CONSOLxx member.

Verify that the MCS console userids are properly restricted. 

If the following guidance is true, this is not a finding.

Each console defined in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) is associated with a valid RACF userid.

Each console userid has no special privileges and/or attributes (e.g., SPECIAL, OPERATIONS, etc.).
Each console userid has no accesses to interactive on-line facilities (e.g., TSO, CICS, etc.; excluding VTAM SMCS consoles).

Each console userid will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and console name in the CONSOLE resource class.

Each console userid has the RACF default group that is an appropriate console group profile.


NOTE:	If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console userids and/or console group may be given with access READ to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resource.

NOTE:	Execute the JCL in CNTL(IRRUT100) using the RACF console userids as SYSIN input. This report lists all occurrences of these userids within the RACF database, including data set and resource access lists.'
  desc 'fix', "Define all consoles identified in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) to be defined to RACF.

Review the MCS console resources defined to z/OS and RACF, and ensure they conform to those outlined below.

Each console defined in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) is associated with a valid RACF userid.

Each console userid has no special privileges and/or attributes (e.g., SPECIAL, OPERATIONS, etc.).

Each console userid has no accesses to interactive on-line facilities (e.g., TSO, CICS, etc.; excluding VTAM SMCS consoles).

Each console userid will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and consolename in the CONSOLE resource class.

Each console userid has the RACF default group that is an appropriate console group profile.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console userids and/or console group may be given with access READ to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resource.

NOTE: Execute the JCL in CNTL(IRRUT100) using the RACF console userids as SYSIN input. This report lists all occurrences of these userids within the RACF database, including data set and resource access lists.

Examples: 
AG consautolog SUPGROUP(<syspsmpl>) OWNER(<syspsmpl>) -
DATA(' group for console userids for autolog processing ')

AG consnoautolog SUPGROUP(<syspsmpl>) OWNER(<syspsmpl>) -
DATA('group for console userids for no autolog processing')

AU consname NAME('CONSOLE USERID FOR consname') NOPASSWORD NOOIDCARD -
DFLTGRP(consautolog) OWNER(consautolog) -
DATA('ADDED TO SUPPORT THE CHANGE TO LOGON(AUTO) IN CONSOLXX')

PERMIT MVS.CONTROL.** CL(OPERCMDS) ID(consautolog) ACCESS(READ)
PERMIT MVS.DISPLAY.** CL(OPERCMDS) ID(consautolog) ACCESS(READ)
PERMIT MVS.MONITOR.** CL(OPERCMDS) ID(consautolog) ACCESS(READ)
PERMIT MVS.STOPMN.** CL(OPERCMDS) ID(consautolog) ACCESS(READ)

PERMIT consname CL(CONSOLE) ID(consname)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25389r514836_chk'
  tag severity: 'medium'
  tag gid: 'V-223716'
  tag rid: 'SV-223716r604139_rule'
  tag stig_id: 'RACF-ES-000690'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25377r514837_fix'
  tag 'documentable'
  tag legacy: ['SV-107243', 'V-98139']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
