control 'SV-35064' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', %q(First determine if (x)inetd is running:
# ps -ef | grep -v "grep" | egrep -i "inetd|xinetd"

Then, determine the contents of the configuration file:
# find / -type f -name xinetd.conf -o -name inetd.conf | xargs -n1 cat | \
	tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//' | grep -v "^#"

If inetd is running and no active services are found (i.e., the configuration file does not exist, is empty or is completely commented out), this is a finding.

If inetd is not running and the configuration file does not exist, is empty or is completely commented out, this is not a finding.

If inetd is running and active services are found via the ps command and are also in the inetd.conf file, this is not a finding.)
  desc 'fix', 'Remove or disable the inetd startup scripts and kill the service.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36522r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12005'
  tag rid: 'SV-35064r1_rule'
  tag stig_id: 'GEN003700'
  tag gtitle: 'GEN003700'
  tag fix_id: 'F-31882r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
