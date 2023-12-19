control 'SV-224545' do
  title 'Vanguard Security Solutions resources must be properly defined and protected.'
  desc 'Program products can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to program product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACP Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(FACILITY)
- RACFCMDS.RPT(FACILITY) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZVSS0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in Vanguard Security Solutions Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The RACF resources are defined with a default access of NONE.

___ The RACF resource access authorizations restrict access to the appropriate personnel.

___ The RACF resource logging requirements are specified.

___ The RACF resource access authorizations are defined with UACC(NONE) and NOWARNING.

___ The RACF resource VSR$.SCOPE allowed READ access when approved and documented by ISSM  or equivalent Security Authority.'
  desc 'fix', "Configure ACP resource definitions in accordance with Vanguard Security Solutions Resources and Vanguard Security Solutions Resources Descriptions tables in the zOS STIG Addendum. These tables list the resources, descriptions, and access and logging requirements. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

(Note: The resources, and/or resource prefixes identified below are examples of a possible installation. The actual resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

The following commands are provided as a sample for implementing resource controls: 

rdef facility vra$.acstask.** uacc(none) owner(admin) -
audit(all(read)) -
data('protected per zvssr020')

pe vra$.acstask.** cl(facility) id(<audtaudt>) acc(read)
pe vra$.acstask.** cl(facility) id(<secaaudt>) acc(read)   
Sample scope definition:
rdef facility vsr$.** uacc(none) owner(admin) audi(a(r)) -      
 data('deny-by-default for Vanguard Advisor Reporter')          
rdef facility vsr$.scope uacc(none) owner(admin) -              
 audit(a(u)) data('Vanguard Advisor Reporter Auth Scope')"
  impact 0.5
  ref 'DPMS Target zOS VSS for RACF'
  tag check_id: 'C-26228r868560_chk'
  tag severity: 'medium'
  tag gid: 'V-224545'
  tag rid: 'SV-224545r868563_rule'
  tag stig_id: 'ZVSSR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26216r868562_fix'
  tag 'documentable'
  tag legacy: ['SV-24912', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
