control 'SV-202105' do
  title 'The network device must prohibit installation of software without explicit privileged status.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system.  This requirement applies to code changes and upgrades for all network devices.'
  desc 'check', 'Determine if the network device prohibits installation of software without explicit privileged status.  This requirement may be verified by demonstration or configuration review.

If installation of software is not prohibited without explicit privileged status, this is a finding.'
  desc 'fix', 'Configure the network device to prohibit installation of software without explicit privileged status.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2231r381944_chk'
  tag severity: 'medium'
  tag gid: 'V-202105'
  tag rid: 'SV-202105r400000_rule'
  tag stig_id: 'SRG-APP-000378-NDM-000302'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-2232r381945_fix'
  tag 'documentable'
  tag legacy: ['SV-69485', 'V-55239']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
