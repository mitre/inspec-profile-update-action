control 'SV-223756' do
  title 'IBM z/OS RJE workstations and NJE nodes must be controlled in accordance with security requirements.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Note that this guidance addresses RJE Workstations that are "Dedicated". If an RJE workstation is dedicated, the assumption is that the RJE to host connection is hard-wired between the RJE and host. In this case the RMT definition statement will contain the keyword LINE= which specifies that this RJE is only connected via that one LINE statement. 

Refer to the JES2PARM member of PARMLIB.

If all of the statements below are true, this is not a finding.

If any of the statements below are untrue, this is a finding.

Review the JES2 parameters for RJE workstation definitions by searching for RMT( in the report.

A userid of RMTnnnn is defined to RACF for each RJE workstation, where nnnn is the number on the RMT statement.

No userid segments (e.g., TSO, CICS, etc.) are defined.

Restricted from accessing all data sets and resources with exception of the corresponding JESINPUT class profile for that remote.

NOTE: Execute the JCL in CNTL(IRRUT100) using the RACF RMTnnnn userids as SYSIN input. This report lists all occurrences of these userids within the RACF database, including data set and resource access lists.

A FACILITY-Class profile exists in the format RJE.RMTnnnn where nnn identifies the remote number.'
  desc 'fix', %q(Note that this guidance addresses RJE Workstations that are "Dedicated". If an RJE workstation is dedicated, the assumption is that the RJE to host connection is hard-wired between the RJE and host. In this case the RMT definition statement will contain the keyword LINE= which specifies that this RJE is only connected via that one LINE statement. 

 Review the JES2 parameters for RJE workstation definitions by searching for RMT( in the report.

 Configure the RJE workstation userids to be defined as follows:

 A userid of RMTnnnn is defined to RACF for each RJE workstation, where nnnn is the number on the RMT statement.

 No userid segments (e.g., TSO, CICS, etc.) are defined.

 Restricted from accessing all data sets and resources with exception of the corresponding JESINPUT-class profile for that remote.

Review Chapter 17 of the RACF Security Admin Guide. The following is an example that show proper implementation:

AG RMTGRP OWNER(ADMIN) SUPGROUP(ADMIN)

AU RMT777 NAME('RMT RJE 777') DFLTGRP(RMTGRP) OWNER(RMTGRP) DATA('COMPLY WITH ZJES0011') NOPASS RESTRICTED

PE RMT777 CL(JESINPUT) ID(RMT777)

 Ensure that a FACILITY-Class profile exists in the format RJE.RMTnnnn where nnn identifies the remote number.

A command example is shown here:

RDEF FACILITY RJE.RMT777 UACC(NONE) OWNER(ADMIN) DATA('COMPLY WITH ZJES0011 FOR RJE 777'))
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25429r514956_chk'
  tag severity: 'medium'
  tag gid: 'V-223756'
  tag rid: 'SV-223756r604139_rule'
  tag stig_id: 'RACF-JS-000120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25417r514957_fix'
  tag 'documentable'
  tag legacy: ['SV-107323', 'V-98219']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
