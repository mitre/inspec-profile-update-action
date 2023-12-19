control 'SV-248892' do
  title 'OL 8 must disable the use of user namespaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
User namespaces are used primarily for Linux container. The value 0 disallows the use of user namespaces. When containers are not in use, namespaces should be disallowed. When containers are deployed on a system, the value should be set to a large non-zero value. The default value is 39078.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify OL 8 disables the use of user namespaces with the following commands. 
 
Note: User namespaces are used primarily for Linux containers. If containers are in use, this requirement is not applicable. 
 
$ sudo sysctl user.max_user_namespaces 
 
user.max_user_namespaces = 0 
 
If the returned line does not have a value of "0" or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r user.max_user_namespaces /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: user.max_user_namespaces = 0

If "user.max_user_namespaces" is not set to "0", is missing or commented out, this is a finding.

If results are returned from more than one file location, this is a finding.'
  desc 'fix', 'Configure the system to disable the use of user namespaces by adding the following line to a file in the "/etc/sysctl.d" directory: 
 
user.max_user_namespaces = 0 
 
The system configuration files must be reloaded for the changes to take effect. To reload the contents of the files, run the following command: 
 
$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52326r818738_chk'
  tag severity: 'medium'
  tag gid: 'V-248892'
  tag rid: 'SV-248892r818739_rule'
  tag stig_id: 'OL08-00-040284'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52280r780241_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
