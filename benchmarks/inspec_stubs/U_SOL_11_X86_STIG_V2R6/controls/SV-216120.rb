control 'SV-216120' do
  title 'Host-based authentication for login-based services must be disabled.'
  desc 'The use of .rhosts authentication is an insecure protocol and can be replaced with public-key authentication using Secure Shell. As automatic authentication settings in the .rhosts files can provide a malicious user with sensitive system credentials, the use of .rhosts files should be disabled.'
  desc 'check', "Note: This is the location for Solaris 11.1. For earlier versions, the information is in /etc/pam.conf.

Determine if host-based authentication services are enabled.

# grep 'pam_rhosts_auth.so.1' /etc/pam.conf /etc/pam.d/*| grep -vc '^#'

If the returned result is not 0 (zero), this is a finding."
  desc 'fix', 'Note: This is the location for Solaris 11.1. For earlier versions, the information is in /etc/pam.conf.

The root role is required.

# ls -l /etc/pam.d
to identify the various configuration files used by PAM.

Search each file for the pam_rhosts_auth.so.1 entry.

# grep pam_rhosts_auth.so.1 [filename]

Identify the file with the line pam_hosts_auth.so.1 in it.

# pfedit [filename]

Insert a comment character (#) at the beginning of the line containing "pam_hosts_auth.so.1".'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17358r372742_chk'
  tag severity: 'medium'
  tag gid: 'V-216120'
  tag rid: 'SV-216120r603268_rule'
  tag stig_id: 'SOL-11.1-040390'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17356r372743_fix'
  tag 'documentable'
  tag legacy: ['V-48113', 'SV-60985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
