control 'SV-45686' do
  title 'The IDPS must block malicious code.'
  desc 'Configuring the IDPS to delete and/or quarantine based on local organizational incident handling procedures minimizes the impact of this code on the network.'
  desc 'check', 'Verify the IDPS blocks malicious code.

If the IDPS does not block malicious code, this is a finding.'
  desc 'fix', 'Configure the IDPS to block malicious code.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-43052r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34762'
  tag rid: 'SV-45686r2_rule'
  tag stig_id: 'SRG-NET-000249-IDPS-00176'
  tag gtitle: 'SRG-NET-000249-IDPS-00176'
  tag fix_id: 'F-39084r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
