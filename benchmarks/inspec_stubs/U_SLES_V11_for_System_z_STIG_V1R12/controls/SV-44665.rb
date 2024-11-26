control 'SV-44665' do
  title 'The Linux PAM system must not grant sole access to admin privileges to the first user who logs into the console.'
  desc 'If an unauthorized user has been granted privileged access while logged in at the console, the security posture of a system could be greatly compromised.  Additionally, such a situation could deny legitimate root access from another terminal.'
  desc 'check', 'Ensure the pam_console.so module is not configured in any files in /etc/pam.d by:

      # cd /etc/pam.d
      # grep pam_console.so *

Or

      #       ls –la /etc/security/console.perms

If either the pam_console.so entry or the file /etc/security/console.perms is found then this is a finding.'
  desc 'fix', 'Ensure PAM is not configured to grant sole access of administrative privileges to the first user logged in at the console. Remove the console.perms file if it exists:
# rm /etc/security/console.perms'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42168r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4346'
  tag rid: 'SV-44665r1_rule'
  tag stig_id: 'GEN000000-LNX00600'
  tag gtitle: 'GEN000000-LNX00600'
  tag fix_id: 'F-38118r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
