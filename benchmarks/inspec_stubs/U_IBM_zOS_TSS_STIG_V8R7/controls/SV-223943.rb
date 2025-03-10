control 'SV-223943' do
  title 'IBM z/OS must properly protect MCS console userid(s).'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Refer to IEASYS00 to determine correct CONSOLxx member.

Examine the CONSOLxx member.

If the following guidance is true, this is not a finding.

Each console defined in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) is associated with a valid TSS ACID.

Each console ACID has no special privileges and/or attributes (e.g., BYPASSING, CONSOLE, etc.; excluding VTAM SMCS consoles).

Each console ACID has no accesses to interactive on-line facilities (e.g., TSO, CICS, etc.; excluding VTAM SMCS consoles). Each console can have the Facility of CONSOLE.

Each console ACID will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and consolename in the CONSOLE resource class.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console ACIDs and/or console profile may be given with access READ to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resource.'
  desc 'fix', "Review the MCS console resources defined to z/OS and the ACP, and ensure they conform to those outlined below.

Each console defined in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) is associated with a valid TSS ACID.

Each console ACID has no special privileges and/or attributes (e.g., BYPASSING, CONSOLE, etc.).

Each console ACID has no accesses to interactive on-line facilities (e.g., TSO, CICS, etc.; excluding VTAM SMCS consoles). 

Each console can have the Facility of CONSOLE.

Each console ACID will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and consolename in the CONSOLE resource class.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console ACIDs and/or console profile may be given with access READ to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resource.

Example: (These are only examples, not requirements.)

TSS CREATE(consnoautolog) TYPE(PROFILE) 
NAME('MCS consoles with no autolog')
DEPT('SYS1')

TSS CREATE(consautolog) TYPE(PROFILE) -
NAME('MCS consoles with autolog') -
DEPT('SYS1')

TSS CREATE(consname) NAME('MCS console name') -
FACILITY(CONSOLE) PASSWORD(password,0) -
PROFILE(consgroup)

TSS PER(consautolog) OPERCMDS(MVS.CONTROL) ACCESS(READ)
TSS PER(consautolog) OPERCMDS(MVS.DISPLAY) ACCESS(READ)
TSS PER(consautolog) OPERCMDS(MVS.MONITOR) ACCESS(READ)
TSS PER(consautolog) OPERCMDS(MVS.STOPMN) ACCESS(READ)

TSS PER(consname) SYSCONS(consname) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25616r516228_chk'
  tag severity: 'medium'
  tag gid: 'V-223943'
  tag rid: 'SV-223943r561402_rule'
  tag stig_id: 'TSS0-ES-000700'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25604r516229_fix'
  tag 'documentable'
  tag legacy: ['V-98593', 'SV-107697']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
