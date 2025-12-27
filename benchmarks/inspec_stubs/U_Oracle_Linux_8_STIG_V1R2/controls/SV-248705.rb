control 'SV-248705' do
  title 'The OL 8 lastlog command must have a mode of "0750" or less permissive.'
  desc 'Unauthorized disclosure of the contents of the /var/log/lastlog file can reveal system data to attackers, thus compromising its confidentiality.'
  desc 'check', 'Verify the "lastlog" command has a mode of "0750" or less permissive with the following command: 
 
$ sudo stat -c "%a %n" /usr/bin/lastlog

750  /usr/bin/lastlog

If the "lastlog" command has a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Configure the mode of the "lastlog" command for OL 8 to "0750" with the following command:  

$ sudo chmod 0750 /usr/bin/lastlog'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52139r779679_chk'
  tag severity: 'medium'
  tag gid: 'V-248705'
  tag rid: 'SV-248705r779681_rule'
  tag stig_id: 'OL08-00-020262'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-52093r779680_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
