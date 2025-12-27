control 'SV-221872' do
  title 'For Oracle Linux operating systems using DNS resolution, at least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', %q(Determine whether the system is using local or DNS name resolution with the following command:

# grep hosts /etc/nsswitch.conf
hosts: files dns

If the DNS entry is missing from the host's line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty.

Verify the "/etc/resolv.conf" file is empty with the following command:

# ls -al /etc/resolv.conf
-rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding.

If the DNS entry is found on the host's line of the "/etc/nsswitch.conf" file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

# grep nameserver /etc/resolv.conf
nameserver 192.168.1.2
nameserver 192.168.1.3

If less than two lines are returned that are not commented out, this is a finding.

Verify the "/etc/resolv.conf" file is immutable with the following command:

# sudo lsattr /etc/resolv.conf

----i----------- /etc/resolv.conf

If the file is mutable and has not been documented with the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', 'Configure the operating system to use two or more name servers for DNS resolution.

Edit the "/etc/resolv.conf" file to uncomment or add the two or more "nameserver" option lines with the IP address of local authoritative name servers. If local host resolution is being performed, the "/etc/resolv.conf" file must be empty. An empty "/etc/resolv.conf" file can be created as follows:

# echo -n > /etc/resolv.conf

And then make the file immutable with the following command:

# chattr +i /etc/resolv.conf

If the "/etc/resolv.conf" file must be mutable, the required configuration must be documented with the Information System Security Officer (ISSO) and the file must be verified by the system file integrity tool.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36328r602578_chk'
  tag severity: 'low'
  tag gid: 'V-221872'
  tag rid: 'SV-221872r603260_rule'
  tag stig_id: 'OL07-00-040600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36292r602579_fix'
  tag 'documentable'
  tag legacy: ['SV-108587', 'V-99483']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
