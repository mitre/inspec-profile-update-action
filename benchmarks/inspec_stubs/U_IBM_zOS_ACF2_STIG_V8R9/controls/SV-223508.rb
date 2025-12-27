control 'SV-223508' do
  title 'ACF2 PSWD GSO record value must be set to prohibit password reuse for a minimum of five generations or more.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST PSWD

If "PSWDXHIST" is not specified, this is a finding.

If "PSWDXHIST#" is set to "5" or greater, this is not a finding'
  desc 'fix', 'Configure Password option "PSWXHST" is coded and "PSWXHST#" is "5" or greater.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25181r695440_chk'
  tag severity: 'medium'
  tag gid: 'V-223508'
  tag rid: 'SV-223508r695441_rule'
  tag stig_id: 'ACF2-ES-000910'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-25169r500658_fix'
  tag 'documentable'
  tag legacy: ['V-97719', 'SV-106823']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
