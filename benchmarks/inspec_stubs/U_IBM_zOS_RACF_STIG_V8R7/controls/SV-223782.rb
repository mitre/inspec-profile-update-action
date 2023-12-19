control 'SV-223782' do
  title 'IBM z/OS must not allow nonexistent or inaccessible LINKLIST libraries.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From and ISPF Command line enter:
TSO ISRDDN LINKLIST

Review the list, if there are any DUMMY entries i.e., inaccessible LINKLIST libraries, this is a finding.'
  desc 'fix', 'Review all entries contained in the LINKLIST for the actual existence of each library. Develop a plan of action to correct deficiencies.

The Linklist is a default set of libraries that MVS searches for a specified program. This facility is used so that a user does not have to know the library names in which utility types of programs are stored. Control over membership in the Linklist is specified within the operating system. The data set SYS1.PARMLIB(LNKLSTxx) is used to specify the library names. (The xx is the suffix designated by the LNK parameter in the IEASYSxx member of SYS1.PARMLIB, or overridden by the computer operator at IPL.)

Use the following recommendations and techniques to control the exposures created by the LINKLIST facility:

-Avoid inclusion of sensitive libraries in the LNKLSTxx member unless absolutely required.

-The LNKLSTxx and PROGxx (LNKLST entries) members will contain only required libraries. On a semiannual basis, Software Support should review the volume serial numbers, and should verify them in accordance with the system catalog. Software Support will remove all nonexistent libraries. The ISSO should modify and/or delete the rules associated with these libraries.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25455r515034_chk'
  tag severity: 'medium'
  tag gid: 'V-223782'
  tag rid: 'SV-223782r604139_rule'
  tag stig_id: 'RACF-OS-000260'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25443r515035_fix'
  tag 'documentable'
  tag legacy: ['V-98271', 'SV-107375']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
