control 'SV-218550' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'check', 'This vulnerability is applicable only to sendmail. If Postfix is the SMTP service for the system this will never be a finding.

Procedure:
Determine if EXPN is disabled.
# grep -v "^#" /etc/mail/sendmail.cf |grep -i PrivacyOptions

If nothing is returned or the returned line does not contain "noexpn", this is a finding.'
  desc 'fix', %q(Rebuild /etc/mail/sendmail.cf with the "noexpn" Privacy Flag set.

Procedure:
Edit /etc/mail/sendmail.mc resetting the Privacy Flags to the default:

define('confPRIVACYFLAGS', 'authwarnings,novrfy,noexpn,restrictqrun')dnl

Rebuild the sendmail.cf file with:
# make -C /etc/mail

Restart the sendmail service.
# service sendmail restart)
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20025r562750_chk'
  tag severity: 'low'
  tag gid: 'V-218550'
  tag rid: 'SV-218550r603259_rule'
  tag stig_id: 'GEN004660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20023r562751_fix'
  tag 'documentable'
  tag legacy: ['V-4692', 'SV-62833']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
