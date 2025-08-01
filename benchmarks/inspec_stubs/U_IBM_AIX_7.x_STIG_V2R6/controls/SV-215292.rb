control 'SV-215292' do
  title 'If GSSAPI authentication is not required on AIX, the SSH daemon must disable GSSAPI authentication.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed."
  desc 'check', %q(Ask the SA if GSSAPI authentication is used for SSH authentication to the system. If so, this is not applicable. 

Check the SSH daemon configuration for the GSSAPI authentication setting: 

# grep -i GSSAPIAuthentication /etc/ssh/sshd_config | grep -v '^#' 
GSSAPIAuthentication no

If the setting is not set to "no", this is a finding.)
  desc 'fix', 'Edit "/etc/ssh/sshd_config" and remove the "GSSAPIAuthentication" setting or change the value to "no".

Refresh sshd:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16490r294327_chk'
  tag severity: 'medium'
  tag gid: 'V-215292'
  tag rid: 'SV-215292r508663_rule'
  tag stig_id: 'AIX7-00-002108'
  tag gtitle: 'SRG-OS-000373-GPOS-00158'
  tag fix_id: 'F-16488r294328_fix'
  tag 'documentable'
  tag legacy: ['SV-101639', 'V-91541']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
