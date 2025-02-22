control 'SV-208808' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc 'The hashes for all user account passwords should be stored in the file "/etc/shadow" and never in "/etc/passwd", which is readable by all users.'
  desc 'check', %q(To check that no password hashes are stored in "/etc/passwd", run the following command: 

# awk -F: '($2 != "x") {print}' /etc/passwd

If it produces any output, then a password hash is stored in "/etc/passwd". 
If any stored hashes are found in /etc/passwd, this is a finding.)
  desc 'fix', 'If any password hashes are stored in "/etc/passwd" (in the second field, instead of an "x"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9061r357404_chk'
  tag severity: 'medium'
  tag gid: 'V-208808'
  tag rid: 'SV-208808r793593_rule'
  tag stig_id: 'OL6-00-000031'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9061r357405_fix'
  tag 'documentable'
  tag legacy: ['SV-64947', 'V-50741']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
