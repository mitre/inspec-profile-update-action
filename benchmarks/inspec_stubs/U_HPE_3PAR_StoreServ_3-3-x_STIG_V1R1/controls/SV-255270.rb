control 'SV-255270' do
  title 'The HPE 3PAR OS must be configured to disable nonessential web-services.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The HPE 3PAR OS does not, by default, operate nonessential services. The web-services component must be configured for it to start. If it is not required by the mission, then it must be disabled.'
  desc 'check', 'Verify the state of the Optional capabilities on the array.

cli% showwsapi

If the service state is not "Disabled", and the web-services functionality is not being used, this is a finding.

If web services functionality is required, this is not applicable.'
  desc 'fix', 'If web services functionality is not required, stop and disable web-services:

cli% stopwsapi -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58943r870127_chk'
  tag severity: 'medium'
  tag gid: 'V-255270'
  tag rid: 'SV-255270r870129_rule'
  tag stig_id: 'HP3P-33-001001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-58887r870128_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
