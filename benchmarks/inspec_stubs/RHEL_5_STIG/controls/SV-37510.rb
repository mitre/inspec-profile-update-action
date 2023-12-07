control 'SV-37510' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'fix', %q(Rebuild /etc/mail/sendmail.cf with the "noexpn" Privacy Flag set.

Procedure:
Edit /etc/mail/sendmail.mc resetting the Privacy Flags to the default:

define('confPRIVACYFLAGS', 'authwarnings,novrfy,noexpn,restrictqrun')dnl

Rebuild the sendmail.cf file with:
# make -C /etc/mail

Restart the sendmail service.
# service sendmail restart)
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-4692'
  tag rid: 'SV-37510r1_rule'
  tag stig_id: 'GEN004660'
  tag gtitle: 'GEN004660'
  tag fix_id: 'F-31421r1_fix'
  tag false_positives: 'False positives may occur with the SMTP EXPN check. According to RFC821, it is acceptable for a server to respond with a 250 (success) or 550 (failure) when the server supports the EXPN command. For example, some servers return "550 EXPN command not available," meaning the command is not supported and the machine is not vulnerable. However, a result of "550 that is a mailing list, not a user" would be a failure code, but not an indication of an error, and the machine would be vulnerable. If a false positive is suspected, check the log file for the response from the server.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
