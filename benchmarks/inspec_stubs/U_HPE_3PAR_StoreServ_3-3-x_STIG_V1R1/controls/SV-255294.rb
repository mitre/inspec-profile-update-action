control 'SV-255294' do
  title 'The HPE 3PAR OS must be configured to disable nonessential VASA VVol services.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The HPE 3PAR OS does not, by default, operate nonessential services. The VASA VVol Provider service component must be configured for it to start. If it is not required by the mission, then it must be disabled.'
  desc 'check', 'Check with the Information Owner whether the mission objectives require VASA VVol functionality.

If the mission requirements include VASA VVol functionality, this requirement is not applicable.

If mission requirements do not include this functionality, verify the state of the VASA VVol services capabilities on the array:

cli% showvasa

If the state is "enabled", this is a finding.'
  desc 'fix', 'Verify with the Information Owner whether VASA VVol functionality is required by the mission objectives.

If the mission requires VASA VVol functionality, this requirement is not applicable.

If VASA VVol services functionality is not required by the mission, stop the VASA provider:

cli% stopvasa -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58967r870199_chk'
  tag severity: 'medium'
  tag gid: 'V-255294'
  tag rid: 'SV-255294r870201_rule'
  tag stig_id: 'HP3P-33-121001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-58911r870200_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
