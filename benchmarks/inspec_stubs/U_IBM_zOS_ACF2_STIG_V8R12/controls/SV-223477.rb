control 'SV-223477' do
  title 'CA-ACF2 must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF to enter ACF2 Command shell
enter SHOW STATE

If "PSWDRSV = NO", this is a finding.

If "PSWDRSVW = NO", this is a finding.

SHOW PSwdopts

Reserved Words and Prefixes
APPL APR ASDF AUG BASIC
CADAM DEC DEMO FEB FOCUS
GAME IBM JAN JUL JUN
LOG MAR MAY NET NEW
NOV OCT PASS ROS SEP
SIGN SYS TEST TSO VALID
VTAM XXX 1234'
  desc 'fix', 'Configure the GSO record to include PSWDRSV and PSWDRSVW.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25150r500563_chk'
  tag severity: 'medium'
  tag gid: 'V-223477'
  tag rid: 'SV-223477r533198_rule'
  tag stig_id: 'ACF2-ES-000590'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-25138r500564_fix'
  tag 'documentable'
  tag legacy: ['V-97653', 'SV-106757']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
