control 'SV-248527' do
  title 'OL 8 must display a banner before granting local or remote access to the system via a graphical user logon.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

'
  desc 'check', 'Note: This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Verify OL 8 displays a banner before granting access to the operating system via a graphical user logon.

Determine if the operating system displays a banner at the logon screen with the following command:

$ sudo grep banner-message-enable /etc/dconf/db/local.d/*

banner-message-enable=true

If "banner-message-enable" is set to "false" or is missing, this is a finding.'
  desc 'fix', 'Configure the operating system to display a banner before granting access to the system.

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/01-banner-message

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

[org/gnome/login-screen]

banner-message-enable=true

Run the following command to update the database:

$ sudo dconf update'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51961r779145_chk'
  tag severity: 'medium'
  tag gid: 'V-248527'
  tag rid: 'SV-248527r779147_rule'
  tag stig_id: 'OL08-00-010049'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-51915r779146_fix'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
