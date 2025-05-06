control 'SV-223691' do
  title 'The IBM z/OS IEASYMUP resource must be protected in accordance with proper security requirements.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.'
  desc 'check', 'From the ISPF Command Shell enter: 
Search all Class(Facility) MASK(ieasymup)

For each entity found enter: 
RL facility <entity>

If RACF resources are defined with a default access of NONE, this is not a finding.

If RACF resource access authorizations restrict UPDATE and/or greater access to appropriate personnel (i.e., DASD administrators, Tape Library personnel, and system programming personnel), this is not a finding.

If RACF resource logging requirements are specified for UPDATE and/or greater access, this is not a finding.'
  desc 'fix', "Ensure that the System level symbolic resources are defined to the FACILITY resource class and protected. UPDATE access to the System level symbolic resources are limited to System Programmers, DASD Administrators, and/or Tape Library personnel. All access is logged. Ensure the guidelines for the resources and/or generic equivalent are followed.

Limit access to the IEASYMUP resources to above personnel with UPDATE and/or greater access.

The following commands are provided as a sample for implementing resource controls:

rdef facility ieasymup.* uacc(none) owner(admin) -
audit(all(read)) -
data('protected per acp00350')
rdef facility ieasymup.symbolname uacc(none) owner(admin) -
audit(all(read)) -
data('protected per acp00350')

pe ieasymup.symbolname cl(facility) id(<dasdsmpl) acc(u)
pe ieasymup.symbolname cl(facility) id(<syspsmpl) acc(u)
pe ieasymup.symbolname cl(facility) id(<tapesmpl) acc(u)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25364r514761_chk'
  tag severity: 'medium'
  tag gid: 'V-223691'
  tag rid: 'SV-223691r853597_rule'
  tag stig_id: 'RACF-ES-000430'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25352r514762_fix'
  tag 'documentable'
  tag legacy: ['V-98087', 'SV-107191']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
