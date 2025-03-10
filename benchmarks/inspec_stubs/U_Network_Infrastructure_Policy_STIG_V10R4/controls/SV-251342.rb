control 'SV-251342' do
  title 'If a Secure File Transfer Protocol (SFTP) server is used to provide updates to the sensors, the server must be configured to allow read-only access to the files within the directory on which the signature packs are placed.'
  desc 'In a large scale IDPS deployment, it is common to have an automated update process implemented. This is accomplished by having the updates downloaded on a dedicated SFTP server within the management network. The SFTP server should be configured to allow read-only access to the files within the directory on which the signature packs are placed, and then only from the account that the sensors will use. The sensors can then be configured to automatically check the SFTP server periodically to look for the new signature packs and to update themselves once they have been tested.'
  desc 'check', 'If the signatures are located on a server, verify that the directories on which the signature packs are placed are protected by read-only access.

If the directories are not set for read-only access, this is a finding.'
  desc 'fix', 'Modify the access restrictions to prevent the signatures from being updated.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54777r805979_chk'
  tag severity: 'medium'
  tag gid: 'V-251342'
  tag rid: 'SV-251342r805981_rule'
  tag stig_id: 'NET-IDPS-029'
  tag gtitle: 'NET-IDPS-029'
  tag fix_id: 'F-54730r805980_fix'
  tag 'documentable'
  tag legacy: ['V-18506', 'SV-20041']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
