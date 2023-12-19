control 'SV-3966' do
  title 'In the event the authentication server is unavailable, the network device must have a single local account of last resort defined.'
  desc "Authentication for administrative access to the device is required at all times. A single account of last resort can be created on the device's local database for use in an emergency such as when the authentication server is down or connectivity between the device and the authentication server is not operable. The console or local account of last resort logon credentials must be stored in a sealed envelope and kept in a safe."
  desc 'check', 'Review the network device configuration to determine if an authentication server is defined for gaining administrative access. If so, there must be only one account of last resort configured locally for an emergency.

Verify the username and password for the local account of last resort is contained within a sealed envelope kept in a safe.

If an authentication server is used and more than one local account exists, this is a finding.'
  desc 'fix', 'Configure the device to only allow one local account of last resort for emergency access and store the credentials in a secure manner.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3502r7_chk'
  tag severity: 'medium'
  tag gid: 'V-3966'
  tag rid: 'SV-3966r6_rule'
  tag stig_id: 'NET0440'
  tag gtitle: 'More than one local account is defined.'
  tag fix_id: 'F-3899r9_fix'
  tag 'documentable'
end
