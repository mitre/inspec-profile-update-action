control 'SV-16259' do
  title 'Network devices must use two or more authentication servers for the purpose of granting administrative access.'
  desc 'The use of Authentication, Authorization, and Accounting (AAA) affords the best methods for controlling user access, authorization levels, and activity logging.  By enabling AAA on the routers in conjunction with an authentication server such as TACACS+ or RADIUS, the administrators can easily add or remove user accounts, add or remove command authorizations, and maintain a log of user activity.

The use of an authentication server provides the capability to assign router administrators to tiered groups that contain their privilege level that is used for authorization of specific commands.   For example, user mode would be authorized for all authenticated administrators while configuration or edit mode should only be granted to those administrators that are permitted to implement router configuration changes.'
  desc 'check', 'Verify an authentication server is required to access the device and that there are two or more authentication servers defined.

If the device is not configured for two separate authentication servers, this is a finding.'
  desc 'fix', 'Configure the device to use two separate authentication servers.'
  impact 0.5
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-14439r6_chk'
  tag severity: 'medium'
  tag gid: 'V-15432'
  tag rid: 'SV-16259r4_rule'
  tag stig_id: 'NET0433'
  tag gtitle: 'The device is not authenticated using a AAA server.'
  tag fix_id: 'F-15096r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
