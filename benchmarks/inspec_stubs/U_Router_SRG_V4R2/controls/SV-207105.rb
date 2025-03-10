control 'SV-207105' do
  title 'The MSDP router must be configured to limit the amount of source-active messages it accepts on per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'Review the router configuration to determine if it is configured to limit the amount of source-active messages it accepts on a per-peer basis.

If the router is not configured to limit the source-active messages it accepts, this is a finding.'
  desc 'fix', 'Configure the MSDP router to limit the amount of source-active messages it accepts from each peer.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7366r382160_chk'
  tag severity: 'low'
  tag gid: 'V-207105'
  tag rid: 'SV-207105r604135_rule'
  tag stig_id: 'SRG-NET-000018-RTR-000009'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7366r382161_fix'
  tag 'documentable'
  tag legacy: ['V-78347', 'SV-93053']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
