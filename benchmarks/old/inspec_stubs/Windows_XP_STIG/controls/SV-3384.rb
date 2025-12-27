control 'SV-3384' do
  title 'The system is not configured to make the object creator the owner of objects created by administrators.'
  desc 'Either the object creator or the Administrators group owns objects created by members of the Administrators group.  In order to ensure accurate auditing and proper accountability, the default owner should be the object creator.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System objects: Default owner for object created by members of the Administrators group” to “Object creator”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3384'
  tag rid: 'SV-3384r1_rule'
  tag gtitle: 'Owner of Objects Created by Administrators'
  tag fix_id: 'F-60r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
