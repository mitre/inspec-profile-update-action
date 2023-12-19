control 'SV-28402' do
  title 'The SMTP service must not have the EXPN feature active.'
  desc 'The SMTP EXPN function allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. EXPN may also provide additional information concerning users on the system, such as the full names of account owners.'
  desc 'check', 'Perform the following to determine if EXPN is disabled:

# telnet localhost 25
expn root

If the command does not return a 500 error code of command unrecognized, this is a finding.

OR

Locate the sendmail.cf configuration file by:

# find / -name sendmail.cf -print
# grep -v "^#" <sendmail.cf location> |grep -i privacyoptions

The O PrivacyOptions should have the noexpn or the goaway option (covering both noexpn and novrfy).
If the EXPN command is not disabled, this is a finding.'
  desc 'fix', 'Edit the sendmail.cf file and add or edit the following line:
O PrivacyOptions=goaway
Restart the Sendmail service.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-655r2_chk'
  tag severity: 'low'
  tag gid: 'V-4692'
  tag rid: 'SV-28402r1_rule'
  tag stig_id: 'GEN004660'
  tag gtitle: 'GEN004660'
  tag fix_id: 'F-25673r1_fix'
  tag false_positives: 'False positives may occur with the SMTP EXPN check. According to RFC821, it is acceptable for a server to respond with a 250 (success) or 550 (failure) when the server supports the EXPN command.  For example, some servers return "550 EXPN command not available," meaning the command is not supported and the machine is not vulnerable.  However, a result of "550 That is a mailing list, not a user" would be a failure code, but not an indication of an error, and the machine would be vulnerable.  If a false positive is suspected, check the log file for the response from the server.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
