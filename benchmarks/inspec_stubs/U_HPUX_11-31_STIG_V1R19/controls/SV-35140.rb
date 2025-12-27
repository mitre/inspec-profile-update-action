control 'SV-35140' do
  title 'The hosts.lpd file (or equivalent) must not contain a "+" character.'
  desc 'Having the "+" character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources.'
  desc 'check', %q(Look for the presence of a print service configuration file. The hosts.lpd file is not used on HP, only inetd.sec, hosts.equiv, and/or the system (lp) .rhosts will apply.

When rlpdaemon is started via inetd, access control is provided via the fileinetd.sec to allow or prevent a host from making print requests.

When rlpdaemon is started at boot via a run command file, all requests must come from one of the machines listed in the file /etc/hosts.equiv or /var/spool/lp/.rhosts.

Procedure:
First, determine the rlpdaemon startup method:

1) Print services started via inetd?
# cat /etc/inetd.conf | grep -v "^#" | grep -c rlpdaemon

If the above command return value is 1, check the services file.

# cat /etc/services | grep -v "^#" | grep printer | grep -c spooler

If the above command return value is 1, check the inetd.sec file.

# cat /var/adm/inetd.sec | grep -v "^#" | tr '\011' ' ' | tr -s ' ' | grep printer | grep allow | grep -c "\+"

If the above command return value is 1, this is a finding.

2) The rlpdaemon is started as a service, and not via inetd. Verify neither the /etc/hosts.equiv nor /var/spool/lp/.rhosts contains a "+":

# cat /etc/hosts.equiv | grep -v "^#" | grep -c "\+"
# cat /var/spool/lp/.rhosts | grep -v "^#" | grep -c "\+"

If the return value of either of the above two command(s) is 1, this is a finding.

If none of the files are found, this check should be marked not a finding. 

Otherwise, examine the configuration file.
# more <print service file>

Check for entries containing a "+" or "_" character. If any are found, this is a finding.)
  desc 'fix', 'Remove the "+" entries from the hosts.lpd (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34997r1_chk'
  tag severity: 'medium'
  tag gid: 'V-827'
  tag rid: 'SV-35140r1_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'GEN003900'
  tag fix_id: 'F-30292r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
