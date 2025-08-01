control 'SV-215438' do
  title 'The AIX operating system must be configured to use Multi Factor Authentication for remote connections.'
  desc 'To assure accountability and prevent unauthenticated access, privileged and non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1. Something you know (e.g., password/PIN);
2. Something you have (e.g., cryptographic identification device, token); and
3. Something you are (e.g., biometric).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify SSH is configured to use multi factor authentication:

# grep ^sshd /etc/pam.conf | head -3

sshd auth required   pam_ckfile
sshd auth required   pam_permission file=/etc/security/access.conf found=allow
sshd auth required   pam_pmfa /etc/security/pmfa/pam_pmfa.conf

If the output does not match the above lines, any lines are missing, or commented out, this is a finding.'
  desc 'fix', 'Add or update the following lines in the /etc/pam.conf file:

sshd auth required   pam_ckfile
sshd auth required   pam_permission file=/etc/security/access.conffound=allow
sshd auth required   pam_pmfa /etc/security/pmfa/pam_pmfa.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16636r294765_chk'
  tag severity: 'medium'
  tag gid: 'V-215438'
  tag rid: 'SV-215438r508663_rule'
  tag stig_id: 'AIX7-00-003202'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16634r294766_fix'
  tag 'documentable'
  tag legacy: ['V-92945', 'SV-103033']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
