control 'SV-234327' do
  title 'The UEM server must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created. 

Satisfies:FAU_GEN.1.1(1)'
  desc 'check', 'Verify the UEM server initiate session auditing upon startup.

If the UEM server does not initiate session auditing upon startup, this is a finding.'
  desc 'fix', 'Configure the UEM server to initiate session auditing upon startup.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37512r613991_chk'
  tag severity: 'medium'
  tag gid: 'V-234327'
  tag rid: 'SV-234327r617355_rule'
  tag stig_id: 'SRG-APP-000092-UEM-000053'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-37477r613992_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
