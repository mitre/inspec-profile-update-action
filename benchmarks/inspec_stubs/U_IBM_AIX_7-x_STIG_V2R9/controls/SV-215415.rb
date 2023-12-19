control 'SV-215415' do
  title 'SMTP service must not have the EXPN or VRFY features active on AIX systems.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners. The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Check the "PrivacyOptions" parameter in "/etc/mail/sendmail.cf":
# grep -v "^#" /etc/mail/sendmail.cf |grep -i privacyoptions 

The above command should yield the following output:
O PrivacyOptions=goaway

The "O PrivacyOptions" should have the "goaway" option (covering both noexpn and novrfy). 

If the "O PrivacyOptions" value does not contain "goaway", this is a finding.'
  desc 'fix', 'Edit the "sendmail.cf" file and add or edit the following line: 
O PrivacyOptions=goaway 

Restart the "Sendmail" service:
# startsrc -s sendmail -a "-bd -q30m"'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16613r294696_chk'
  tag severity: 'medium'
  tag gid: 'V-215415'
  tag rid: 'SV-215415r508663_rule'
  tag stig_id: 'AIX7-00-003117'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16611r294697_fix'
  tag 'documentable'
  tag legacy: ['V-91663', 'SV-101761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
