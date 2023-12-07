control 'SV-1136' do
  title 'Users are not forcibly disconnected when logon hours expire.'
  desc 'Users should not be permitted to remain logged on to the network after they have exceeded their permitted logon hours.  In many cases, this indicates that a user forgot to log off before leaving for the day.  However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Disconnect Clients When Logon Hours Expire” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1136'
  tag rid: 'SV-1136r1_rule'
  tag gtitle: 'Forcibly Disconnect when Logon Hours Expire'
  tag fix_id: 'F-6572r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
