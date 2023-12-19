control 'SV-37294' do
  title 'The system must require passwords contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so maxrepeat=3

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11975'
  tag rid: 'SV-37294r1_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'GEN000680'
  tag fix_id: 'F-31243r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
