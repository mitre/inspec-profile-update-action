control 'SV-248634' do
  title 'For OL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', %q(Determine whether the system is using local or DNS name resolution with the following command: 
 
$ sudo grep hosts /etc/nsswitch.conf 
 
hosts: files dns 
 
If the DNS entry is missing from the host's line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty. 
 
Verify the "/etc/resolv.conf" file is empty with the following command: 
 
$ sudo ls -al /etc/resolv.conf 
 
-rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf 
 
If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding. 
 
If the DNS entry is found on the host's line of the "/etc/nsswitch.conf" file, verify the operating system is configured to use two or more name servers for DNS resolution. 
 
Determine the name servers used by the system with the following command: 
 
$ sudo grep nameserver /etc/resolv.conf 
 
nameserver 192.168.1.2 
nameserver 192.168.1.3 
 
If fewer than two lines are returned that are not commented out, this is a finding.)
  desc 'fix', 'Configure OL 8 to use two or more name servers for DNS resolution. 
 
By default, "NetworkManager" on OL 8 dynamically updates the "/etc/resolv.conf" file with the DNS settings from active "NetworkManager" connection profiles. However, this feature can be disabled to allow manual configurations. 
 
If manually configuring DNS, edit the "/etc/resolv.conf" file to uncomment or add the two or more "nameserver" option lines with the IP address of local authoritative name servers.  
 
If local host resolution is being performed, the "/etc/resolv.conf" file must be empty. An empty "/etc/resolv.conf" file can be created as follows: 
 
$ sudo echo -n > /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52068r779466_chk'
  tag severity: 'medium'
  tag gid: 'V-248634'
  tag rid: 'SV-248634r779468_rule'
  tag stig_id: 'OL08-00-010680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52022r779467_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
