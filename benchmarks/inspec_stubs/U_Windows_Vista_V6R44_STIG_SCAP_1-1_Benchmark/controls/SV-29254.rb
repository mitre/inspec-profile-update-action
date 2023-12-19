control 'SV-29254' do
  title 'Domain Controller authentication is not required to unlock the workstation.'
  desc 'This setting controls the behavior of the system when you attempt to unlock the workstation.  If this setting is enabled, the system will pass the credentials to the domain controller (if in a domain) for authentication before allowing the system to be unlocked.  This will be set to disabled per the FDCC.'
  desc 'fix', 'Workstations - Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Require domain controller authentication to unlock workstation” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-3375'
  tag rid: 'SV-29254r1_rule'
  tag gtitle: 'Domain Controller authentication for unlock'
  tag fix_id: 'F-22888r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
