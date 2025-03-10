control 'SV-227859' do
  title 'The ftpusers file must have mode 0640 or less permissive.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification.  Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', 'Check the permissions of the ftpusers file.
# ls -l /etc/ftpd/ftpusers
If the ftpusers file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the ftpusers file to 0640.
# chmod 0640 /etc/ftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30021r489970_chk'
  tag severity: 'medium'
  tag gid: 'V-227859'
  tag rid: 'SV-227859r854509_rule'
  tag stig_id: 'GEN004940'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30009r489971_fix'
  tag 'documentable'
  tag legacy: ['V-843', 'SV-28413']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
