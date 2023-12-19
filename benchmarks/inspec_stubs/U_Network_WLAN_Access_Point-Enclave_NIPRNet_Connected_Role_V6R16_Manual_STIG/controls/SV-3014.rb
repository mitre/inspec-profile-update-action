control 'SV-3014' do
  title 'The network devices must timeout management connections for administrative access after 10 minutes or less of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled between the managed network device and a PC or terminal server when the later has been left unattended. In addition quickly terminating an idle session will also free up resources committed by the managed network device as well as reduce the risk of a management session from being hijacked. Setting the timeout of the session to 10 minutes or less increases the level of protection afforded critical network components.'
  desc 'check', 'Review the management connection for administrative access and verify the network device is configured to time-out the connection at 10 minutes or less of inactivity.

If the device does not terminate inactive management connections at 10 minutes or less, this is a finding.'
  desc 'fix', 'Configure the network devices to ensure the timeout for unattended administrative access connections is no longer than 10 minutes.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3540r6_chk'
  tag severity: 'medium'
  tag gid: 'V-3014'
  tag rid: 'SV-3014r4_rule'
  tag stig_id: 'NET1639'
  tag gtitle: 'Management connection does not timeout.'
  tag fix_id: 'F-3039r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
