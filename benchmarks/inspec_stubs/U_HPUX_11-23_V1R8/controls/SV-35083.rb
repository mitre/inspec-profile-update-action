control 'SV-35083' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', %q(Determine if VRFY is disabled.
# telnet localhost 25
vrfy root

If the command does not return a 500 error code of command unrecognized, this is a finding.
OR
Check the sendmail.cf configuration file by:
# cat  /etc/mail/sendmail.cf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | grep -v "^#" | \
grep -i privacyoptions | egrep -c -i "goaway|novrfy"

Ensure the VRFY command is disabled with an entry in the sendmail.cf file. The entry could be any one of Opnovrfy, novrfy, or goaway, which could also have other options included, such as noexpn. The goaway argument encompasses many things, such as novrfy and noexpn.

If no setting to disable VRFY is found, this is a finding.)
  desc 'fix', 'If running Sendmail, add the line Opnovrfy to the Sendmail configuration file, usually located in /etc/mail/sendmail.cf. For other mail servers, contact the vendor for information on how to disable the verify command. Newer versions of Sendmail are available at http://www.sendmail.org or from ftp://ftp.cs.berkeley.edu/ucb/sendmail.   

Edit the /etc/mail/sendmail.cf  file and add or edit (one of) the following line(s):
O PrivacyOptions=novrfy 
O PrivacyOptions=goaway

Then  restart the Sendmail service.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36576r1_chk'
  tag severity: 'low'
  tag gid: 'V-4693'
  tag rid: 'SV-35083r1_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'GEN004680'
  tag fix_id: 'F-31944r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
