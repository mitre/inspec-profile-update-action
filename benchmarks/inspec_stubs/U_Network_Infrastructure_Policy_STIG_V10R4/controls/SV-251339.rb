control 'SV-251339' do
  title 'Sensor traffic in transit must be protected at all times via an Out-of-Band (OOB) network or an encrypted tunnel between site locations.'
  desc 'User interface services must be physically or logically separated from data storage and management services. Data from IDS sensors must be protected by confidentiality controls; from being lost and altered.'
  desc 'check', 'Review the network topology diagram and interview the ISSO to determine how the IDS sensor data is transported between sites.

If it is not transported across an OOB network or an encrypted tunnel, this is a finding.'
  desc 'fix', 'Design a communications path for OOB traffic or create an encrypted tunnel using a FIPS 140-2 validated encryption algorithm to protect data.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54774r805970_chk'
  tag severity: 'medium'
  tag gid: 'V-251339'
  tag rid: 'SV-251339r805972_rule'
  tag stig_id: 'NET-IDPS-024'
  tag gtitle: 'NET-IDPS-024'
  tag fix_id: 'F-54727r805971_fix'
  tag 'documentable'
  tag legacy: ['V-18496', 'SV-20031']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
