control 'SV-234605' do
  title 'The UEM server must be maintained at a supported version.'
  desc 'The UEM vendor maintains specific product versions for a specific period of time. MDM/EMM server versions no longer supported by the vendor will not receive security updates for new vulnerabilities, which leaves them subject to exploitation. 

Satisfies:FPT_TUD_EXT.1.1, FPT_TUD_EXT.1.2 
Reference:PP-MDM-414005'
  desc 'check', 'Verify the UEM server is maintained at a supported version.

If the UEM server is not maintained at a supported version, this is a finding.'
  desc 'fix', 'Configure the UEM server to be maintained at a supported version.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37790r615449_chk'
  tag severity: 'high'
  tag gid: 'V-234605'
  tag rid: 'SV-234605r617355_rule'
  tag stig_id: 'SRG-APP-000456-UEM-000330'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-37755r615450_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
