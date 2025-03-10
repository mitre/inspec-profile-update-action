control 'SV-248893' do
  title 'OL 8 must use reverse path filtering on all IPv4 interfaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
Enabling reverse path filtering drops packets with source addresses that are not routable. There is no equivalent filter for IPv6 traffic.
The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 uses reverse path filtering on all IPv4 interfaces with the following commands: 
 
$ sudo sysctl net.ipv4.conf.all.rp_filter 
 
net.ipv4.conf.all.rp_filter = 1 
 
If the returned line does not have a value of "1" or "2" or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.rp_filter /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not set to "1", is missing or commented out, this is a finding.

If results are returned from more than one file location, this is a finding.'
  desc 'fix', 'Configure the system to use reverse path filtering on all IPv4 interfaces by adding the following line to a file in the "/etc/sysctl.d" directory: 
 
net.ipv4.conf.all.rp_filter = 1 
 
The system configuration files must be reloaded for the changes to take effect. To reload the contents of the files, run the following command: 
 
$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52327r818740_chk'
  tag severity: 'medium'
  tag gid: 'V-248893'
  tag rid: 'SV-248893r818741_rule'
  tag stig_id: 'OL08-00-040285'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52281r780244_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
