control 'SV-4692' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute-force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'check', 'Determine if EXPN is disabled.

Procedure:
# telnet localhost 25
expn root

If the command does not return a 500 error code of command unrecognized, this is a finding.

OR

Locate the sendmail.cf configuration file.

Procedure:
# find / -name sendmail.cf -print
# grep -v "^#" <sendmail.cf location> | egrep -i "(goaway|noexpn)"

Verify the EXPN command is disabled with an entry in the sendmail.cf file that reads as one of the following:

Opnoexpn
O PrivacyOptions=noexpn
Opgoaway
O PrivacyOptions=goaway

(Other privacy options, such as novrfy or noetrn, may be included in the same line, separated by commas.  The goaway option encompasses a number of privacy options, including noexpn.)  If the EXPN command is not disabled, this is a finding.'
  desc 'fix', 'Edit the sendmail.cf file and add Opnoexpn option.
Restart the Sendmail service.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28638r1_chk'
  tag severity: 'low'
  tag gid: 'V-4692'
  tag rid: 'SV-4692r2_rule'
  tag stig_id: 'GEN004660'
  tag gtitle: 'GEN004660'
  tag fix_id: 'F-4620r2_fix'
  tag false_positives: 'False positives may occur with the SMTP EXPN check. According to RFC821, it is acceptable for a server to respond with a 250 (success) or 550 (failure) when the server supports the EXPN command.  For example, some servers return "550 EXPN command not available", meaning the command is not supported and the machine is not vulnerable.  However, a result of "550 That is a mailing list, not a user" would be a failure code, but not an indication of an error, and the machine would be vulnerable.  If false positive is suspected, check the log file for the response from the server.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
