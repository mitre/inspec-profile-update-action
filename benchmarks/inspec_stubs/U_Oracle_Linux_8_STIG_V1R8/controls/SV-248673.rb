control 'SV-248673' do
  title 'OL 8 must disable the user list at logon for graphical user interfaces.'
  desc 'Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to enumerate known user accounts without authenticated access to the system.'
  desc 'check', 'Note: This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify the operating system disables the user logon list for graphical user interfaces with the following command:

$ sudo gsettings get org.gnome.login-screen disable-user-list
true

If the setting is "false", this is a finding.'
  desc 'fix', 'Configure the operating system to disable the user list at logon for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 
Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/02-login-screen

[org/gnome/login-screen]
disable-user-list=true

Update the system databases:
$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52107r779583_chk'
  tag severity: 'medium'
  tag gid: 'V-248673'
  tag rid: 'SV-248673r779585_rule'
  tag stig_id: 'OL08-00-020032'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52061r779584_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
