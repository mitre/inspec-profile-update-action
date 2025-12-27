control 'SV-215431' do
  title 'AIX must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Check if "/etc/security/.profile" contains the proper "umask" setting by running the following command:
# grep "umask 077" /etc/security/.profile
umask 077

If the above command does not output the "umask 077", this is a finding.

From the command prompt, run the following command to check if "umask=077" for the default stanza in "/etc/security/user":
# lssec -f /etc/security/user -s default -a umask
default umask=077

If the "umask" for the default stanza is not "077", or the "umask" is not set, this is a finding.'
  desc 'fix', 'Add the following line to "/etc/security/.profile":
umask 077

Run the following command to set "umask=077" for the default stanza in "/etc/security/user":
# chsec -f /etc/security/user -s default -a umask=077'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16629r294744_chk'
  tag severity: 'medium'
  tag gid: 'V-215431'
  tag rid: 'SV-215431r508663_rule'
  tag stig_id: 'AIX7-00-003137'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-16627r294745_fix'
  tag 'documentable'
  tag legacy: ['V-91735', 'SV-101833']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
