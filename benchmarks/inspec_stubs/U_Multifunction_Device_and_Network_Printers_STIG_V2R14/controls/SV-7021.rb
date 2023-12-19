control 'SV-7021' do
  title 'Print spoolers are  not configured to restrict access to authorized users and restrict users to managing their own individual jobs.'
  desc 'If unauthorized users are allowed access to the print spooler they can queue large print file creating a denial of service for other users.  If users are not restricted to manipulating only files they created, they could create ad denial of service by changing the print order of existing files or deleting other users files.
The SA will ensure print spoolers are configured to restrict access to authorized user and restrict users to managing their own individual jobs.'
  desc 'check', 'The reviewer will, with the assistance of the SA, verify that the print spoolers are configured to restrict access to authorized users and restrict users to managing their own individual jobs.'
  desc 'fix', 'Configure the print spoolers to restrict access to authorized users and restrict users to managing their own individual jobs.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3002r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6796'
  tag rid: 'SV-7021r1_rule'
  tag stig_id: 'MFD05.001'
  tag gtitle: 'MFD Authorized Users Restrictions'
  tag fix_id: 'F-6463r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAN-1, IAIA-1, IAIA-2'
end
