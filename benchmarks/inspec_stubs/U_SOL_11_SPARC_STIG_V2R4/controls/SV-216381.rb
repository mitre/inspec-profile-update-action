control 'SV-216381' do
  title 'The system must implement TCP Wrappers.'
  desc 'TCP Wrappers is a host-based access control system that allows administrators to control who has access to various network services based on the IP address of the remote end of the connection. TCP Wrappers also provides logging information via syslog about both successful and unsuccessful connections.

TCP Wrappers provides granular control over what services can be accessed over the network. Its logs show attempted access to services from non-authorized systems, which can help identify unauthorized access attempts.'
  desc 'check', %q(Determine if TCP Wrappers is configured.

# inetadm -p | grep tcp_wrappers

If the output of this command is "FALSE", this is a finding.

The above command will check whether TCP Wrappers is enabled for all TCP-based services started by inetd. TCP Wrappers are enabled by default for sendmail and SunSSH (version 0.5.11). The use of OpenSSH access is controlled by the sshd_config file starting with Solaris
11.3. SunSSH is removed starting with Solaris 11.4.

Individual inetd services may still be configured to use TCP Wrappers even if the global parameter (above) is set to "FALSE". To check the status of individual inetd services, use the command:


# for svc in `inetadm | awk '/svc:\// { print $NF }'`; do
val=`inetadm -l ${svc} | grep -c tcp_wrappers=TRUE`
if [ ${val} -eq 1 ]; then
echo "TCP Wrappers enabled for ${svc}"
fi
done

If the required services are not configured to use TCP Wrappers, this is finding.

# ls /etc/hosts.deny
# ls /etc/hosts.allow

If these files are not found, this is a finding.)
  desc 'fix', 'The root role is required.

Configure allowed and denied hosts per organizational policy.

1. Create and customize the policy in /etc/hosts.allow:

# echo "ALL: [net]/[mask] , [net]/[mask], ..." > /etc/hosts.allow

where each [net>/[mask> combination (for example, the Class C address block "192.168.1.0/255.255.255.0") can represent one network block in use by the organization that requires access to this system.

2. Create a default deny policy in /etc/hosts.deny: # echo "ALL: ALL" >/etc/hosts.deny

3. Enable TCP Wrappers for all services started by inetd: 

# inetadm -M tcp_wrappers=TRUE'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17617r371231_chk'
  tag severity: 'low'
  tag gid: 'V-216381'
  tag rid: 'SV-216381r603267_rule'
  tag stig_id: 'SOL-11.1-050140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17615r371232_fix'
  tag 'documentable'
  tag legacy: ['SV-61093', 'V-48221']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
