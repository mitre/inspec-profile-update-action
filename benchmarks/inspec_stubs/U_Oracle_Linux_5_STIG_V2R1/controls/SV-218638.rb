control 'SV-218638' do
  title 'The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL.'
  desc 'SWAT is a tool used to configure Samba.  It modifies Samba configuration, which can impact system security, and must be protected from unauthorized access.  SWAT authentication may involve the root password, which must be protected by encryption when traversing the network.

Restricting access to the local host allows for the use of SSH TCP forwarding, if configured, or administration by a web browser on the local system.'
  desc 'check', 'SWAT is a tool for configuring Samba and should only be found on a system with a requirement for Samba. If SWAT is used, it must be utilized with SSL to ensure a secure connection between the client and the server.

Procedure:

# grep -H "bin/swat" /etc/xinetd.d/*|cut -d: -f1 |xargs grep "only_from"

If the value of the "only_from" line in the "xinetd.d" file which starts "/usr/sbin/swat" is not "localhost" or the equivalent, this is a finding.'
  desc 'fix', 'Disable SWAT or require SWAT is only accessed via SSH.

Procedure:
If SWAT is not needed for operation of the system remove the SWAT package:
# rpm -qa|grep swat

Remove "samba-swat" or "samba3x-swat" depending on which one is installed
# rpm --erase samba-swat
or
# rpm --erase samba3x-swat

If SWAT is required but not at all times disable it when it is not needed.
Modify the /etc/xinetd.d file for "swat" to contain a "disable = yes" line.

To access using SSH:
Follow vendor configuration documentation to create an stunnel for SWAT.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20113r562891_chk'
  tag severity: 'medium'
  tag gid: 'V-218638'
  tag rid: 'SV-218638r603259_rule'
  tag stig_id: 'GEN006080'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20111r562892_fix'
  tag 'documentable'
  tag legacy: ['V-1026', 'SV-64123']
  tag cci: ['CCI-000381', 'CCI-001436']
  tag nist: ['CM-7 a', 'AC-17 (8)']
end
