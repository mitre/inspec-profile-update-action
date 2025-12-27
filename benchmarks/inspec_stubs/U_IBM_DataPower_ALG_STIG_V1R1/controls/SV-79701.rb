control 'SV-79701' do
  title 'The DataPower Gateway must protect audit information from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Login page >> Enter non-admin user id and password, select Default for domain >> Click Login. 

If non-admin user can log on, this is a finding.'
  desc 'fix', 'Privileged account user log on to default domain >> Administration >> Access >> User Account >> Select non-privileged user account >> Click “…” button next to User Group field >> Enter */default/*?Access=NONE into field >> Click add >> Click Apply >> Click Apply >> Click Save Configuration.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65211'
  tag rid: 'SV-79701r1_rule'
  tag stig_id: 'WSDP-AG-000028'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-71151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
