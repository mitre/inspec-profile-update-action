control 'SV-202131' do
  title 'The network device must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Check the network device to determine if only authorized administrators have permissions for changes, deletions and updates on the network device. Inspect the maintenance log to verify changes are being made only by the system administrators.

If unauthorized users are allowed to change the hardware or software, this is a finding.'
  desc 'fix', 'Configure the network device to enforce access restrictions associated with changes to the system components.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2257r382067_chk'
  tag severity: 'medium'
  tag gid: 'V-202131'
  tag rid: 'SV-202131r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000335'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2258r382068_fix'
  tag 'documentable'
  tag legacy: ['SV-69543', 'V-55297']
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
