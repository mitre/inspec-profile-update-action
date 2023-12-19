control 'SV-223500' do
  title 'CA-ACF2 must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If PSWDPLST is coded as defined in CA ACF2 for z/OS Administration Guide, this is not a finding.'
  desc 'fix', 'Configure Password option PSWDPLST as defined in CA ACF2 for z/OS Administration Guide.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25173r695423_chk'
  tag severity: 'medium'
  tag gid: 'V-223500'
  tag rid: 'SV-223500r695424_rule'
  tag stig_id: 'ACF2-ES-000820'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-25161r500634_fix'
  tag 'documentable'
  tag legacy: ['V-97699', 'SV-106803']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
