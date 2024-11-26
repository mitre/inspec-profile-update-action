control 'SV-40017' do
  title 'The site must have a written policy or training materials stating Bluetooth must be disabled on all applicable devices unless they employ FIPS 140-2 validated cryptographic modules for data-in-transit.'
  desc 'Policy and training provide assurance that security requirements will be implemented in practice. Failure to use FIPS 140-2 validated cryptography makes data more vulnerable to security breaches.'
  desc 'check', 'NOTE: this check only applies to sites using Bluetooth or Zigbee radios.

Interview the IAO and verify a written policy or training materials exists stating that Bluetooth (or Zigbee) will be disabled on all applicable devices unless they employ FIPS 140-2 validated cryptographic modules for data-in-transit.
Mark as a finding if policy does not exist or if it does not adequately cover the requirement.'
  desc 'fix', 'The IAO will ensure there is a policy or training materials prohibiting use of Bluetooth data transmission without FIPS 140-2 validated cryptographic modules.'
  impact 0.3
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-39030r1_chk'
  tag severity: 'low'
  tag gid: 'V-30360'
  tag rid: 'SV-40017r1_rule'
  tag stig_id: 'WIR0401'
  tag gtitle: 'Bluetooth policy and training'
  tag fix_id: 'F-34126r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCT-1'
end
