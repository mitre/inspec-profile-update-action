control 'SV-3967' do
  title 'The network devices must time out access to the console port at 10 minutes or less of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition quickly terminating an idle session will also free up resources committed by the managed network device. Setting the timeout of the session to 10 minutes or less increases the level of protection afforded critical network components.'
  desc 'check', 'Review the configuration and verify a session using the console port will time out after 10 minutes or less of inactivity.

If console access is not configured to timeout at 10 minutes or less, this is a finding.'
  desc 'fix', 'Configure the timeout for idle console connection to 10 minutes or less.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3511r5_chk'
  tag severity: 'medium'
  tag gid: 'V-3967'
  tag rid: 'SV-3967r4_rule'
  tag stig_id: 'NET1624'
  tag gtitle: 'The console port does not timeout after 10 minutes.'
  tag fix_id: 'F-3900r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
