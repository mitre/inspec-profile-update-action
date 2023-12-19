control 'SV-71057' do
  title 'The operating system, for PKI-based authentication, must implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  desc 'Without configuring a local cache of revocation data, there is the potential to allow access to users who are no longer authorized (users with revoked certificates).'
  desc 'check', 'Verify the operating system, for PKI-based authentication, implements a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system, for PKI-based authentication, to implement a local cache of revocation data to support path discovery and validation in case of the inability to access revocation information via the network.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57369r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56797'
  tag rid: 'SV-71057r1_rule'
  tag stig_id: 'SRG-OS-000384-GPOS-00167'
  tag gtitle: 'SRG-OS-000384-GPOS-00167'
  tag fix_id: 'F-61695r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
