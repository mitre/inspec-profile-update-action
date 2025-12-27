control 'SV-223490' do
  title 'ACF2 LINKLST GSO record if specified must only contains trusted system data sets.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'From the ACF Command screen enter:
SET CONTROL(GSO)
LIST LINKLST

If the GSO LINKLST record values conform to the following requirements, this is not a finding.

Specifies one or more partitioned data sets considered part of the system link (SYS1.LINKLIB) during data set access validation. Only trusted system data sets will be listed. Application libraries will never be included. 

Example: 
LIBRARY(SYS1.LINKLIB SYS2A.FDR.LOADLIB) 

If there is any deviation from the above requirements in the GSO LINKLST record values, this is a finding.'
  desc 'fix', 'Configure the LINKLIST GSO value if specified only contains trusted system data sets.

Specifies one or more partitioned data sets considered part of the system link (SYS1.LINKLIB) during data set access validation.

Only trusted system data sets will be listed. Application libraries will never be included.

Example:
SET C(GSO)
INSERT LINKLST LIBRARY(SYS1.LINKLIB SYS2A.FDR.LOADLIB)

F ACF2,REFRESH(LINKLST)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25163r504576_chk'
  tag severity: 'medium'
  tag gid: 'V-223490'
  tag rid: 'SV-223490r533198_rule'
  tag stig_id: 'ACF2-ES-000720'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-25151r504577_fix'
  tag 'documentable'
  tag legacy: ['V-97679', 'SV-106783']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
