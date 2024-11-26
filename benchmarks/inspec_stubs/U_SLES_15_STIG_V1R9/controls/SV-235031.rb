control 'SV-235031' do
  title 'The SUSE operating system must not allow unattended or automatic logon via the graphical user interface (GUI).'
  desc 'Failure to restrict system access to authenticated users negatively impacts SUSE operating system security.'
  desc 'check', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Verify the SUSE operating system does not allow unattended or automatic logon via the GUI.

Check that unattended or automatic login is disabled with the following commands:

> grep -i ^DISPLAYMANAGER_AUTOLOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_AUTOLOGIN=""

> grep -i ^DISPLAYMANAGER_PASSWORD_LESS_LOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"

If the "DISPLAYMANAGER_AUTOLOGIN" parameter includes a username or the
"DISPLAYMANAGER_PASSWORD_LESS_LOGIN"
If parameter is not set to "no", this is a finding.'
  desc 'fix', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Configure the SUSE operating system GUI to not allow unattended or automatic logon to the system.

Add or edit the following lines in the "/etc/sysconfig/displaymanager"
configuration file:

DISPLAYMANAGER_AUTOLOGIN=""
DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38219r619362_chk'
  tag severity: 'high'
  tag gid: 'V-235031'
  tag rid: 'SV-235031r877377_rule'
  tag stig_id: 'SLES-15-040430'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-38182r619363_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
