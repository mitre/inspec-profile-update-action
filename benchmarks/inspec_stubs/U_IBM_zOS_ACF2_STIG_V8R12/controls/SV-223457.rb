control 'SV-223457' do
  title 'IBM z/OS IEASYMUP resource must be protected in accordance with proper security requirements.'
  desc 'Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'From the ACF Command screen enter:
SET RESOURCE(FAC)
LIST IEASYMUP

If the accesses for IEASYMUP resources and/or generic equivalent are properly restricted, this is not a finding.

The ACF2 resources are defined with a default access of PREVENT.
The ACF2 resource access authorizations state that SERVICE(UPDATE) and/or greater access to DASD administrators, Tape Library personnel, and system programming personnel.
The ACF2 resource logging requirements are specified.'
  desc 'fix', "Configure the System level symbolic resources to be defined to the FACILITY resource class and protected. UPDATE access to the System level symbolic resources are limited to System Programmers, DASD Administrators, and/or Tape Library personnel. All access is logged. Ensure the guidelines for the resources and/or generic equivalent are followed.

Limit access to the IEASYMUP resources to the above personnel with LOG and SERVICE(UPDATE) and/or greater access.

The following commands are provided as a sample for implementing resource controls:

$KEY(IEASYMUP) TYPE(FAC)
- UID(<dasd>) SERVICE(UPDATE) LOG
- UID(<sysprgmr>) SERVICE(UPDATE) LOG
- UID(<tape librarian>) SERVICE(UPDATE) LOG
- UID(*) PREVENT

SET R(FAC)
COMPILE 'ACF2.FAC(IEASYMUP)' STORE

F ACF2,REBUILD(FAC)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25130r504500_chk'
  tag severity: 'medium'
  tag gid: 'V-223457'
  tag rid: 'SV-223457r877392_rule'
  tag stig_id: 'ACF2-ES-000370'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25118r853522_fix'
  tag 'documentable'
  tag legacy: ['V-97611', 'SV-106715']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
