control 'SV-218181' do
  title 'The Linux PAM system must not grant sole access to admin privileges to the first user who logs into the console.'
  desc 'If an unauthorized user has been granted privileged access while logged in at the console, the security posture of a system could be greatly compromised.  Additionally, such a situation could deny legitimate root access from another terminal.'
  desc 'check', 'Ensure the pam_console.so module is not configured in any files in /etc/pam.d by:

	#  cd /etc/pam.d
	#  grep pam_console.so *

Or

	# 	ls -la /etc/security/console.perms

If either the pam_console.so entry or the file /etc/security/console.perms is found then this is a finding.'
  desc 'fix', 'Configure PAM to not grant sole access of administrative privileges to the first user logged in at the console.  

Identify any instances of pam_console.

# cd /etc/pam.d
# grep pam_console.so *

For any files containing an un-commented reference to pam_console.so, edit the file and remove or comment out the reference.

Remove the console.perms file if it exists:
# rm /etc/security/console.perms'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19656r553880_chk'
  tag severity: 'medium'
  tag gid: 'V-218181'
  tag rid: 'SV-218181r603259_rule'
  tag stig_id: 'GEN000000-LNX00600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19654r553881_fix'
  tag 'documentable'
  tag legacy: ['V-4346', 'SV-63003']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
