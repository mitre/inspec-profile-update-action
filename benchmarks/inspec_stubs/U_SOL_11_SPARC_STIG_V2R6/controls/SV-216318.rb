control 'SV-216318' do
  title 'TCP Wrappers must be enabled and configured per site policy to only allow access by approved hosts and services.'
  desc 'TCP Wrappers are a host-based access control system that allows administrators to control who has access to various network services based on the IP address of the remote end of the connection. TCP Wrappers also provide logging information via syslog about both successful and unsuccessful connections.'
  desc 'check', 'Check that TCP Wrappers are enabled and the host.deny and host.allow files exist.

# inetadm -p | grep tcp_wrappers

If the output of this command is "tcp_wrappers=FALSE", this is a finding.

# ls /etc/hosts.deny
/etc/hosts.deny
# ls /etc/hosts.allow
/etc/hosts.allow

If these files do not exist or do not contain the names of allowed or denied hosts, this is a finding.'
  desc 'fix', 'The root role is required.

To enable TCP Wrappers, run the following commands:

1. Create and customize your policy in /etc/hosts.allow:
# echo "ALL: [net]/[mask], [net]/[mask], ..." > /etc/hosts.allow 

where each [net>/[mask> combination (for example, the Class C address block "192.168.1.0/255.255.255.0") can represent one network block in use by your organization that requires access to this system.

2. Create a default deny policy in /etc/hosts.deny: 

# echo "ALL: ALL" >/etc/hosts.deny

3. Enable TCP Wrappers for all services started by inetd:

# inetadm -M tcp_wrappers=TRUE

The versions of SunSSH (0.5.11) and sendmail that ship with Solaris 11 will automatically use TCP Wrappers to filter access if a hosts.allow or hosts.deny file exists.

The use of OpenSSH access is controlled by the sshd_config file starting with Solaris 11.3. 

SunSSH is removed starting with Solaris 11.4.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17554r371042_chk'
  tag severity: 'medium'
  tag gid: 'V-216318'
  tag rid: 'SV-216318r603267_rule'
  tag stig_id: 'SOL-11.1-030050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17552r371043_fix'
  tag 'documentable'
  tag legacy: ['SV-60807', 'V-47935']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
