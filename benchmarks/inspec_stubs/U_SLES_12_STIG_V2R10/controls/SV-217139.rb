control 'SV-217139' do
  title 'The SUSE operating system must not allow unattended or automatic logon via the graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively impacts SUSE operating system security.'
  desc 'check', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Verify the SUSE operating system does not allow unattended or automatic logon via a graphical user interface.

Check that unattended or automatic login is disabled with the following commands:

> grep -i ^DISPLAYMANAGER_AUTOLOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_AUTOLOGIN=""

> grep -i ^DISPLAYMANAGER_PASSWORD_LESS_LOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"

If the "DISPLAYMANAGER_AUTOLOGIN" parameter includes a username or the
"DISPLAYMANAGER_PASSWORD_LESS_LOGIN" parameter is not set to "no", this is a
finding.'
  desc 'fix', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Configure the SUSE operating system graphical user interface to not allow unattended or automatic logon to the system.

Add or edit the following lines in the "/etc/sysconfig/displaymanager" configuration file:

DISPLAYMANAGER_AUTOLOGIN=""
DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18367r646705_chk'
  tag severity: 'high'
  tag gid: 'V-217139'
  tag rid: 'SV-217139r877377_rule'
  tag stig_id: 'SLES-12-010380'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-18365r646706_fix'
  tag 'documentable'
  tag legacy: ['SV-91829', 'V-77133']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
