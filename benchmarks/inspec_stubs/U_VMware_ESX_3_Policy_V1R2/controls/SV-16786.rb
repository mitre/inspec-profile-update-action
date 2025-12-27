control 'SV-16786' do
  title 'The IAO/SA does not subscribe to vendor security patches and update notifications.'
  desc 'Organizations need to stay current with all applicable ESX Server software updates that are released from VMware. In order to be aware of updates as they are released, virtualization server administrators will subscribe to ESX Server vendor security notices, updates, and patches to ensure that all new vulnerabilities are known. New ESX Server patches and updates should be reviewed in a test environment for the ESX Server before moving them into a production environment.'
  desc 'check', 'Ask the IAO/SA to provide actual update notification to verify that they are on the subscription list.  The email subscription for VMware is security-announce@lists.vmware.com. If no emails or documentation can be provided, this is a finding.'
  desc 'fix', 'Subscribe to vendor security and patch notifications.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16193r1_chk'
  tag severity: 'low'
  tag gid: 'V-15845'
  tag rid: 'SV-16786r1_rule'
  tag stig_id: 'ESX0460'
  tag gtitle: 'No subscription to VMware vendor website'
  tag fix_id: 'F-15799r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
