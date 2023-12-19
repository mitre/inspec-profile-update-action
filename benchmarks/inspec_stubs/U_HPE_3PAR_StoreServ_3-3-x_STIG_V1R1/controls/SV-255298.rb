control 'SV-255298' do
  title 'The HPE 3PAR OS must be configured to disable nonessential Remote Copy services.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The HPE 3PAR OS does not, by default, operate nonessential services. The Remote Copy services component must be configured for it to start. If it is not required by the mission, then it must be disabled.'
  desc 'check', 'Verify with the Information Owner that the mission objectives exclude Remote Copy functionality.

If Remote Copy is required by the mission, this requirement is not applicable.

If Remote Copy is not required by the mission, verify the state of RC functionality: 

cli% showrcopy

If the output is an error and indicates the system is not licensed for Remote Copy, this is not a finding.

If the output indicates "Remote Copy is not configured for this system", this is not a finding.

If the output indicates any other status, this is a finding.'
  desc 'fix', 'Verify with the Information Owner that the mission objectives do not require remote copy.

If Remote Copy is not required by the mission, forcibly stop the functionality, and clear the configuration:

cli% stoprcopy -f -clear'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58971r870284_chk'
  tag severity: 'medium'
  tag gid: 'V-255298'
  tag rid: 'SV-255298r870284_rule'
  tag stig_id: 'HP3P-33-131001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-58915r870212_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
