control 'SV-223491' do
  title 'IBM z/OS must properly protect MCS console userid(s).'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Refer to IEASYS00 to determine the correct CONSOLxx member. 

Examine the CONSOLxx member.

Verify that the MCS console logonids are properly restricted. 

If the following guidance is true, this is not a finding.

Each console defined in the currently active CONSOLxx parmlib member is associated with a valid ACF2 logonid.

Each console logonid has no special privileges and/or attributes (e.g., ACCOUNT, SECURITY, etc.).

Each console logonid has no accesses to interactive online facilities (e.g., TSO, CICS, etc., excluding VTAM SMCS consoles).

Each console logonid will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and consolename in the CONSOLE resource class.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console logonids may be given with SERVICE(READ) to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resources.

NOTE: Execute the JCL in CNTL(ACFRPTRX) using the ACF2 console userids in the LID statements in the SYSIN input. This report lists all occurrences of these userids within the ACF2 database, including data set and resource access lists.'
  desc 'fix', "Define all consoles identified in the currently active CONSOLxx parmlib member in EXAM.RPT(PARMLIB) to be defined to the ESM.

Review the MCS console resources defined to z/OS and the ESM and ensure they conform to those outlined below.

Each console defined in the currently active CONSOLxx parmlib member is associated with a valid ACF2 logonid.

Each console logonid has no special privileges and/or attributes (e.g., ACCOUNT, SECURITY, etc.,  excluding VTAM SMCS consoles).

Each console logonid has no accesses to interactive online facilities (e.g., TSO, CICS, etc.).

Each console logonid will be restricted from accessing all data sets and resources except MVS.MCSOPER.consolename in the OPERCMDS resource class and consolename in the CONSOLE resource class.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console logonids may be given with SERVICE(READ) to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resources.

NOTE: If LOGON(AUTO) is specified in the currently active CONSOLxx parmlib member, additional access may be required. Permissions for the console logonids may be given with SERVICE(READ) to MVS.CONTROL, MVS.DISPLAY, MVS.MONITOR, and MVS.STOPMN OPERCMDS resources.

Example:
INSERT MVAC20 NAME(MVA CONSOLE C20) PASSWORD(xxxxxxxx)

$KEY(MVS) TYPE(OPR)
MCSOPER.- UID(MVAC20) SERVICE(READ) ALLOW
CONTROL.- UID(MVAC20) SERVICE(READ) ALLOW DATA(FOR LOGON(AUTO))
MONITOR.- UID(MVAC20) SERVICE(READ) ALLOW DATA(FOR LOGON(AUTO))
STOPMN.- UID(MVAC20) SERVICE(READ) ALLOW DATA(FOR LOGON(AUTO))
DISPLAY.- UID(*) SERVICE(READ) ALLOW
- UID(*) PREVENT

SET R(OPR)
COMPILE ' ACF2.MVA.OPR(MVS)' STORE

F ACF2,REBUILD(OPR)

$KEY(consname) TYPE(CON)
UID(MVAC20) SERVICE(READ) ALLOW

SET R(CON)
COMPILE ' ACF2.MVA.CON(consname)' STORE

F ACF2,REBUILD(CON)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25164r504579_chk'
  tag severity: 'medium'
  tag gid: 'V-223491'
  tag rid: 'SV-223491r533198_rule'
  tag stig_id: 'ACF2-ES-000730'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25152r504580_fix'
  tag 'documentable'
  tag legacy: ['SV-106785', 'V-97681']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
