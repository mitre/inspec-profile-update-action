control 'SV-255290' do
  title 'The HPE 3PAR OS must be configured to disable nonessential Common Information Model services.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The HPE 3PAR OS does not, by default, operate nonessential services. The Common Information Model services component must be configured for it to start. If it is not required by the mission, then it must be disabled.'
  desc 'check', 'Check with the Information Owner to verify if the mission objectives require CIM functionality.

If the mission requirements include CIM service capabilities, this requirement is not applicable.

If mission requirements do not include CIM, then verify the state of the CIM services capabilities on the array:

cli% showcim

If the service state is not "Disabled", this is a finding.'
  desc 'fix', 'Verify with the Information Owner whether mission objectives require CIM functionality.

If CIM services functionality is not part of the mission requirements, stop and disable "cimserver":

cli% stopcim -f

cli%  setcim -f -http disable -https disable'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58963r870187_chk'
  tag severity: 'medium'
  tag gid: 'V-255290'
  tag rid: 'SV-255290r870189_rule'
  tag stig_id: 'HP3P-33-111001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-58907r870188_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
