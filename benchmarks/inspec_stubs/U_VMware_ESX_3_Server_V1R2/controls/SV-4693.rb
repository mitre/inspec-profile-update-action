control 'SV-4693' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute-force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Determine if VRFY is disabled.

Procedure:
# telnet localhost 25
vrfy root

If the command does not return a 500 error code of command unrecognized, this is a finding.

OR

Locate the sendmail.cf configuration file.

Procedure:
# find / -name sendmail.cf -print
# grep -v "^#" <sendmail.cf location> |grep -i "(goaway|vrfy)"

Verify the VRFY command is disabled with an entry in the sendmail.cf file that reads as one of the following:

Opnovrfy
O PrivacyOptions=novrfy
Opgoaway
O PrivacyOptions=goaway

(Other privacy options, such as noexpn or noetrn, may be included in the same line, separated by commas.  The goaway option encompasses a number of privacy options, including novrfy.)  If the VRFY command is not disabled, this is a finding.'
  desc 'fix', 'If Sendmail is running, add the line Opnovrfy to the Sendmail configuration file, usually located in /etc/sendmail.cf. For other mail servers, contact the vendor for information on how to disable the verify command. Newer versions of Sendmail are available at http://www.sendmail.org or from ftp://ftp.cs.berkeley.edu/ucb/sendmail.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-705r2_chk'
  tag severity: 'low'
  tag gid: 'V-4693'
  tag rid: 'SV-4693r2_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'GEN004680'
  tag fix_id: 'F-4621r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
