control 'SV-29215' do
  title 'Ejection of removable NTFS media is not restricted to Administrators.'
  desc 'Removable hard drives can be formatted and ejected by others who are not members of the Administrators Group, if they are not properly configured.  Formatting and ejecting removable NTFS media should only be done by administrators.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Allowed to Format and Eject Removable Media” to “Administrators”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1171'
  tag rid: 'SV-29215r1_rule'
  tag gtitle: 'Format and Eject Removable Media'
  tag fix_id: 'F-113r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
