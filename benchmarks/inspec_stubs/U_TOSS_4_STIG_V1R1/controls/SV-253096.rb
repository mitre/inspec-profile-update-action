control 'SV-253096' do
  title 'TOSS must prevent the use of dictionary words for passwords.'
  desc 'If TOSS allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify TOSS prevents the use of dictionary words for passwords.

Determine if the field "dictcheck" is set in the "/etc/security/pwquality.conf" or "/etc/security/pwquality.conf.d/*.conf" files with the following command:

$ sudo grep -r dictcheck /etc/security/pwquality.conf /etc/security/pwquality.conf.d

/etc/security/pwquality.conf:dictcheck=1

If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56549r824958_chk'
  tag severity: 'medium'
  tag gid: 'V-253096'
  tag rid: 'SV-253096r824960_rule'
  tag stig_id: 'TOSS-04-040540'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-56499r824959_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
