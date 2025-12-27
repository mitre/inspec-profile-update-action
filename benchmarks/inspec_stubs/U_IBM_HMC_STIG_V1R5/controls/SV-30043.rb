control 'SV-30043' do
  title 'Hardware Management Console management must be accomplished by using the out-of-band or direct connection method.'
  desc 'Removing the management traffic from the production network diminishes the security profile of the Hardware Management Console servers by allowing all the management ports to be closed on the production network. The System Administrator will ensure that Hardware Management Console management is accomplished using the out-of-band or direct connection method.'
  desc 'check', 'The System Administrator will validate that the Hardware Management Console management connection will use TCP/IP with encryption on an out-of-band network.

If the Hardware Management Console management connection does not use TCP/IP with encryption on an out-of-band network then this is a FINDING.'
  desc 'fix', 'The System Administrator will work with the NSO to see that the Hardware Management Console management is set up with encryption on an out-of band network.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24373'
  tag rid: 'SV-30043r2_rule'
  tag stig_id: 'HMC0200'
  tag gtitle: 'HMC0200'
  tag fix_id: 'F-26797r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Network Security Officer', 'Systems Programmer']
  tag ia_controls: 'DCBP-1'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
