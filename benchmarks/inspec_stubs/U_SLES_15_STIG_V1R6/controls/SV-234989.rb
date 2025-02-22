control 'SV-234989' do
  title 'The SUSE operating system must disable the x86 Ctrl-Alt-Delete key sequence for Graphical User Interfaces.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical user interface environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', "Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Verify the SUSE operating system is not configured to reboot the system
when Ctrl-Alt-Delete is pressed in the graphical user interface.

Check that the dconf setting was disabled to allow the Ctrl-Alt-Delete
sequence in the graphical user interface with the following command:

Check the default logout key sequence:

> sudo gsettings get org.gnome.settings-daemon.plugins.media-keys logout
['']

Check that the value is not writable and cannot be changed by the user:

> sudo gsettings writable org.gnome.settings-daemon.plugins.media-keys logout
false

If the logout value is not [''] and the writable status is not false, this
is a finding."
  desc 'fix', "Configure the system to disable the Ctrl-Alt-Delete sequence for the
graphical user interface.

Create a database to contain the system-wide setting (if it does not
already exist) with the following steps:

1. Create a user profile and with the listed content:

/etc/dconf/profile/user
user-db:user
system-db:local

2. Create the following directories:

> sudo mkdir -p /etc/dconf/db/local.d/
> sudo mkdir -p /etc/dconf/db/local.d/locks/

3. Add the following files with the listed content:

/etc/dconf/db/local.d/01-fips-settings
[org/gnome/settings-daemon/plugins/media-keys]
logout=['']

/etc/dconf/db/local.d/locks/01-fips-locks 
/org/gnome/settings-daemon/plugins/media-keys/logout

4. Update the dconf database: 

> sudo dconf update"
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38177r619236_chk'
  tag severity: 'high'
  tag gid: 'V-234989'
  tag rid: 'SV-234989r622137_rule'
  tag stig_id: 'SLES-15-040061'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38140r619237_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
