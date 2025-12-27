control 'SV-3381' do
  title 'The system is not configured to recommended LDAP client signing requirements.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting should be set to Negotiate signing or Require signing depending on the environment and type of LDAP server in use.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: LDAP client signing requirements” to “Negotiate signing” at a minimum.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3381'
  tag rid: 'SV-3381r1_rule'
  tag gtitle: 'LDAP Client Signing'
  tag fix_id: 'F-143r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
