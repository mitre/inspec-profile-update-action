control 'SV-206675' do
  title 'The firewall must immediately use updates made to policy enforcement mechanisms such as firewall rules, security policies, and security zones.'
  desc 'Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the Ports, Protocols, Services Management [PPSM] Category Assurance Levels [CAL] list, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.'
  desc 'check', 'Verify the firewall immediately uses updates made to policy enforcement mechanisms such as firewall rules, security policies, and security zones. For example, there is no need to reinitialize or reboot or the action to commit the changes is prompted.

If the firewall does not immediately use updates made to policy enforcement mechanisms such as firewall rules, security policies, and security zones, this is a finding.'
  desc 'fix', 'Require system administrators to commit and test changes upon configuration of the firewall.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6932r297804_chk'
  tag severity: 'medium'
  tag gid: 'V-206675'
  tag rid: 'SV-206675r604133_rule'
  tag stig_id: 'SRG-NET-000019-FW-000004'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-6932r297805_fix'
  tag 'documentable'
  tag legacy: ['SV-94133', 'V-79427']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
