control 'SV-6773' do
  title 'SAN management is not accomplished using the out-of-band or direct connection method.'
  desc 'Removing the management traffic from the production network diminishes the security profile of the SAN servers by allowing all the management ports to be closed on the production network.
The IAO/NSO will ensure that SAN management is accomplished using the out-of-band or direct connection method.'
  desc 'check', 'The reviewer will interview the IAO and view the SAN network drawings provided.'
  desc 'fix', 'Develop a plan to migrate the SAN management to an out-of-band network or a direct connect method.  Obtain CM approval for the plan and implement the plan.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2537r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6636'
  tag rid: 'SV-6773r1_rule'
  tag stig_id: 'SAN04.013.00'
  tag gtitle: 'SAN management out-of-band or direct connect'
  tag fix_id: 'F-6233r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
