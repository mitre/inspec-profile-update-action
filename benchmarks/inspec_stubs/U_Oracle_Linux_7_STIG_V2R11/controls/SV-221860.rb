control 'SV-221860' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.'
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
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23575r419652_chk'
  tag severity: 'medium'
  tag gid: 'V-221860'
  tag rid: 'SV-221860r853722_rule'
  tag stig_id: 'OL07-00-040430'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-23564r419653_fix'
  tag 'documentable'
  tag legacy: ['V-99459', 'SV-108563']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
