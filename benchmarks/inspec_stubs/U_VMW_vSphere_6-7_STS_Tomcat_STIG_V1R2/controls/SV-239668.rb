control 'SV-239668' do
  title 'The Security Token Service directory tree must have permissions in an "out-of-the-box" state.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled. The Security Token Service files must be adequately protected with correct permissions as applied out of the box.

'
  desc 'check', "Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# find /usr/lib/vmware-sso/vmware-sts/ -xdev -type f -a '(' -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If the command produces any output, this is a finding."
  desc 'fix', 'Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# chown root:root <file_name>

Repeat the command for each file that was returned.

Note: Replace <file_name> for the name of the file that was returned.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42901r816727_chk'
  tag severity: 'medium'
  tag gid: 'V-239668'
  tag rid: 'SV-239668r816729_rule'
  tag stig_id: 'VCST-67-000017'
  tag gtitle: 'SRG-APP-000211-WSR-000030'
  tag fix_id: 'F-42860r816728_fix'
  tag satisfies: ['SRG-APP-000211-WSR-000030', 'SRG-APP-000380-WSR-000072']
  tag 'documentable'
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1) (a)']
end
