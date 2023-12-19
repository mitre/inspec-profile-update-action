control 'SV-226996' do
  title 'The SSH client must not permit GSSAPI authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed."
  desc 'check', "Check the SSH clients configuration for the GSSAPI authentication setting.
# grep -i GSSAPIAuthentication /etc/ssh/ssh_config | grep -v '^#' 
If no lines are returned, or the setting is set to yes, this is a finding."
  desc 'fix', 'Edit the SSH client configuration and set (add if necessary) a  GSSAPIAuthentication directive set to no.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36416r602851_chk'
  tag severity: 'low'
  tag gid: 'V-226996'
  tag rid: 'SV-226996r603265_rule'
  tag stig_id: 'GEN005525'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36380r602852_fix'
  tag 'documentable'
  tag legacy: ['V-22474', 'SV-26767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
