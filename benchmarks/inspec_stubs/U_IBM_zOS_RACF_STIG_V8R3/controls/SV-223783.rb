control 'SV-223783' do
  title 'IBM z/OS must not allow nonexistent or inaccessible Link Pack Area (LPA) libraries.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From and ISPF Command line enter:
TSO ISRDDN LPA

Review the list, if there are any DUMMY entries i.e., inaccessible LPA libraries, this is a finding.'
  desc 'fix', 'Review all entries contained in the LPA members for the actual existence of each library. Develop a plan of action to correct deficiencies. 

The system Link Pack Area (LPA) is the component of MVS that maintains core operating system functions resident in main storage. A security concern exists when libraries from which LPA modules are obtained require APF authorization.

Control over residence in the LPA is specified within the operating system in the following members of the data set SYS1.PARMLIB:

-LPALSTxx specifies the names of libraries to be concatenated to SYS1.LPALIB when the LPA is generated at IPL in an MVS/XA or MVS/ESA system. (The xx is the suffix designated by the LPA parameter in the IEASYSxx member of SYS1.PARMLIB or overridden by the computer operator at system initial program load [IPL].)

-IEAFIXxx specifies the names of modules from SYS1.SVCLIB, the LPALSTxx concatenation, and the LNKLSTxx concatenation that are to be temporarily fixed in central storage in the Fixed LPA (FLPA) for the duration of an IPL. (The xx is the suffix designated by the FIX parameter in the IEASYSxx member of SYS1.PARMLIB or overridden by the computer operator at IPL.)

-IEALPAxx specifies the names of modules that will be loaded from the following:

? SYS1.SVCLIB
? The LPALSTxx concatenation
? The LNKLSTxx concatenation as a temporary extension to the existing Pageable

LPA (PLPA) in the Modified LPA (MLPA) for the duration of an IPL. (The xx is the suffix designated by the MLPA parameter in the IEASYSxx member of SYS1.PARMLIB or overridden by the computer operator at IPL.)

Use the following recommendations and techniques to control the exposures created by the LPA facility:

-The LPALSTxx, IEAFIXxx, and IEALPAxx members will contain only required libraries. On a semiannual basis, Software Support should review the volume serial numbers, and should verify them in accordance with the system catalog. Software Support will remove all nonexistent libraries. The ISSO should modify and/or delete the rules associated with these libraries.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25456r515037_chk'
  tag severity: 'medium'
  tag gid: 'V-223783'
  tag rid: 'SV-223783r604139_rule'
  tag stig_id: 'RACF-OS-000270'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25444r515038_fix'
  tag 'documentable'
  tag legacy: ['V-98273', 'SV-107377']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
