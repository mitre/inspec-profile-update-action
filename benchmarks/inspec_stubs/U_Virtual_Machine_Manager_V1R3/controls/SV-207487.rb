control 'SV-207487' do
  title 'The VMM, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', 'Verify the VMM, for PKI-based authentication, implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM, for PKI-based authentication, to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7744r365865_chk'
  tag severity: 'medium'
  tag gid: 'V-207487'
  tag rid: 'SV-207487r854661_rule'
  tag stig_id: 'SRG-OS-000384-VMM-001580'
  tag gtitle: 'SRG-OS-000384'
  tag fix_id: 'F-7744r365866_fix'
  tag 'documentable'
  tag legacy: ['SV-71535', 'V-57275']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
