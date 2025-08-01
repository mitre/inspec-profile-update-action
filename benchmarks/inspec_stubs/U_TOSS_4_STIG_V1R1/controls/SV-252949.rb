control 'SV-252949' do
  title 'TOSS must automatically lock graphical user sessions after 15 minutes of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify TOSS initiates a session lock after at most a 15-minute period of inactivity for graphical user interfaces with the following commands:

Note: This requirement assumes the use of the TOSS default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.desktop.session idle-delay
uint32 900

If "idle-delay" is set to "0" or a value greater than "900", this is a finding.'
  desc 'fix', 'Configure the operating system to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/00-screensaver

Edit /etc/dconf/db/local.d/00-screensaver and add or update the following lines:

[org/gnome/desktop/session]
# Set the lock time out to 900 seconds before the session is considered idle
idle-delay=uint32 900

Update the system databases:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56402r824169_chk'
  tag severity: 'medium'
  tag gid: 'V-252949'
  tag rid: 'SV-252949r824171_rule'
  tag stig_id: 'TOSS-04-020030'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-56352r824170_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
