control 'SV-39171' do
  title 'The SMTP service must not have the VRFY feature active.'
  desc 'The VRFY (Verify) command allows an attacker to determine if an account exists on a system, providing significant assistance to a brute force attack on user accounts. VRFY may provide additional information about users on the system, such as the full names of account owners.'
  desc 'check', 'Determine if VRFY is disabled. 
Procedure: # telnet localhost 25 
vrfy root
If the command does not return a 500 error code of command unrecognized, this is a finding.

OR

Locate the sendmail.cf configuration file. 
Procedure:
# find / -name sendmail.cf -print # grep -v "^#" |grep -i vrfy 

Ensure the VRFY command is disabled with an entry in the sendmail.cf file. The entry could be any one of Opnovrfy, novrfy, or goaway, which could also have other options included, such as noexpn. The goaway argument encompasses many things, such as novrfy and noexpn.

If no setting to disable VRFY is found, this is a finding.'
  desc 'fix', 'If you are running Sendmail, add the line Opnovrfy to your Sendmail configuration file, usually located in /etc/sendmail.cf. For other mail servers, contact the vendor for information on how to disable the verify command. Newer versions of Sendmail are available at http://www.sendmail.org or from ftp://ftp.cs.berkeley.edu/ucb/sendmail.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38150r1_chk'
  tag severity: 'low'
  tag gid: 'V-4693'
  tag rid: 'SV-39171r1_rule'
  tag stig_id: 'GEN004680'
  tag gtitle: 'GEN004680'
  tag fix_id: 'F-33425r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
