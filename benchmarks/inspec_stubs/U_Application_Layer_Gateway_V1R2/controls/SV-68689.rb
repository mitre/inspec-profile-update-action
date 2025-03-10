control 'SV-68689' do
  title 'The ALG must protect audit information from unauthorized read access.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured network element. Thus, it is imperative that the collected log data from the various network elements, as well as the auditing tools, be secured and can only be accessed by authorized personnel.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG protects audit information from unauthorized read access.

If the ALG does not protect audit information from unauthorized read access, this is a finding.'
  desc 'fix', 'Configure the ALG to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54443'
  tag rid: 'SV-68689r1_rule'
  tag stig_id: 'SRG-NET-000098-ALG-000056'
  tag gtitle: 'SRG-NET-000098-ALG-000056'
  tag fix_id: 'F-59297r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
