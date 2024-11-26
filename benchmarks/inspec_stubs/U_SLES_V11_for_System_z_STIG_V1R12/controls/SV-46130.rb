control 'SV-46130' do
  title 'The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL.'
  desc 'SWAT is a tool used to configure Samba.  It modifies Samba configuration, which can impact system security, and must be protected from unauthorized access.  SWAT authentication may involve the root password, which must be protected by encryption when traversing the network.

Restricting access to the local host allows for the use of SSH TCP forwarding, if configured, or administration by a web browser on the local system.'
  desc 'check', 'SWAT is a tool for configuring Samba and should only be found on a system with a requirement for Samba. If SWAT is used, it must be utilized with SSH to ensure a secure connection between the client and the server.

Procedure:

# grep -H "bin/swat" /etc/xinetd.d/*|cut -d: -f1 |xargs grep "only_from"

If the value of the "only_from" line in the "xinetd.d" file which starts with "/usr/sbin/swat" does not contain "localhost" or the equivalent, this is a finding.'
  desc 'fix', 'Disable SWAT or require that SWAT is only accessed via SSH.

Procedure:

If SWAT is required, but not at all times, disable it when it is not needed.
Modify the /etc/xinetd.d file for "swat" to contain a "disable = yes" line.

To access using SSH:
Follow vendor configuration documentation to create an stunnel for SWAT.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43389r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1026'
  tag rid: 'SV-46130r1_rule'
  tag stig_id: 'GEN006080'
  tag gtitle: 'GEN006080'
  tag fix_id: 'F-39472r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
