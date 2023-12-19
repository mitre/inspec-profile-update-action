control 'SV-204598' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system. GSSAPI authentication must be disabled unless needed."
  desc 'check', 'Verify the SSH daemon does not permit GSSAPI authentication unless approved.

Check that the SSH daemon does not permit GSSAPI authentication with the following command:

# grep -i gssapiauth /etc/ssh/sshd_config
GSSAPIAuthentication no

If the "GSSAPIAuthentication" keyword is missing, is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "GSSAPIAuthentication" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "no": 

GSSAPIAuthentication no

The SSH service must be restarted for changes to take effect.

If GSSAPI authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4722r88986_chk'
  tag severity: 'medium'
  tag gid: 'V-204598'
  tag rid: 'SV-204598r603261_rule'
  tag stig_id: 'RHEL-07-040430'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-4722r88987_fix'
  tag 'documentable'
  tag legacy: ['V-72259', 'SV-86883']
  tag cci: ['CCI-000318', 'CCI-001812', 'CCI-001813', 'CCI-000368', 'CCI-001814']
  tag nist: ['CM-3 f', 'CM-11 (2)', 'CM-5 (1) (a)', 'CM-6 c', 'CM-5 (1)']
end
