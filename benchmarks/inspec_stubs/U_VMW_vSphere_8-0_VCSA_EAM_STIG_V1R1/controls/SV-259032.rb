control 'SV-259032' do
  title 'The vCenter ESX Agent Manager service files must have permissions in an out-of-the-box state.'
  desc 'As a rule, accounts on a web server are to be kept to a minimum. Only administrators, web managers, developers, auditors, and web authors require accounts on the machine hosting the web server. The resources to which these accounts have access must also be closely monitored and controlled.'
  desc 'check', "At the command prompt, run the following command:

# find /usr/lib/vmware-eam/web/ -xdev -type f -a '(' -perm -o+w -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w <file>
# chown root:root <file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA EAM'
  tag check_id: 'C-62772r934752_chk'
  tag severity: 'medium'
  tag gid: 'V-259032'
  tag rid: 'SV-259032r934754_rule'
  tag stig_id: 'VCEM-80-000144'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-62681r934753_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
