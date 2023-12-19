control 'SV-207122' do
  title 'The router must be configured to log all packets that have been dropped.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being done or attempted to be done, and by whom, to compile an accurate risk assessment. Auditing the actions on network devices provides a means to recreate an attack or identify a configuration mistake on the device.'
  desc 'check', 'Review the router interface access control lists (ACLs) to verify all deny statements are logged.

If packets being dropped are not logged, this is a finding.'
  desc 'fix', 'Configure interface ACLs to log all deny statements.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7383r382259_chk'
  tag severity: 'low'
  tag gid: 'V-207122'
  tag rid: 'SV-207122r604135_rule'
  tag stig_id: 'SRG-NET-000078-RTR-000001'
  tag gtitle: 'SRG-NET-000078'
  tag fix_id: 'F-7383r382260_fix'
  tag 'documentable'
  tag legacy: ['V-78229', 'SV-92935']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
