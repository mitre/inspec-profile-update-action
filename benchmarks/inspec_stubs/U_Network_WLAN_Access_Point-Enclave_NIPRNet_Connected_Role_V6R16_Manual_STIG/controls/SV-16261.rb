control 'SV-16261' do
  title 'The emergency administration account must be set to an appropriate authorization level to perform necessary administrative functions when the authentication server is not online.'
  desc 'The emergency administration account is to be configured as a local account on the network devices. It is to be used only when the authentication server is offline or not reachable via the network. The emergency account must be set to an appropriate authorization level to perform necessary administrative functions during this time.'
  desc 'check', 'Review the emergency administration account configured on the network devices and verify that it has been assigned to a privilege level that will enable the administrator to perform necessary administrative functions when the authentication server is not online.

If the emergency administration account is configured for more access than needed to troubleshoot issues, this is a finding.'
  desc 'fix', 'Assign a privilege level to the emergency administration account to allow the administrator to perform necessary administrative functions when the authentication server is not online.'
  impact 0.7
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-14441r6_chk'
  tag severity: 'high'
  tag gid: 'V-15434'
  tag rid: 'SV-16261r5_rule'
  tag stig_id: 'NET0441'
  tag gtitle: 'Emergency administration account privilege level is not set.'
  tag fix_id: 'F-15098r7_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
