control 'SV-221658' do
  title 'The Oracle Linux operating system must uniquely identify and must authenticate users using multifactor authentication via a graphical user logon.'
  desc 'To assure accountability and prevent unauthenticated access, users must be identified and authenticated to prevent potential misuse and compromise of the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

'
  desc 'check', 'Verify the operating system uniquely identifies and authenticates users using multifactor authentication via a graphical user logon.

Note: If the system does not have GNOME installed, this requirement is Not Applicable. 

Determine which profile the system database is using with the following command:

# grep system-db /etc/dconf/profile/user

system-db:local

Note: The example is using the database local for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than local is being used.

# grep enable-smartcard-authentication /etc/dconf/db/local.d/*

enable-smartcard-authentication=true

If "enable-smartcard-authentication" is set to "false" or the keyword is missing, this is a finding.'
  desc 'fix', 'Configure the operating system to uniquely identify and authenticate users using multifactor authentication via a graphical user logon.

Note: If the system does not have GNOME installed, this requirement is Not Applicable.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 

Note: The example is using the local system database, so if the system is using another database in "/etc/dconf/profile/user", create the file under the appropriate subdirectory.

# touch /etc/dconf/db/local.d/00-defaults

Edit "[org/gnome/login-screen]" and add or update the following line:
enable-smartcard-authentication=true 

Update the system databases:
# dconf update'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23373r419046_chk'
  tag severity: 'medium'
  tag gid: 'V-221658'
  tag rid: 'SV-221658r603260_rule'
  tag stig_id: 'OL07-00-010061'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-23362r419047_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00161', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag legacy: ['SV-108161', 'V-99057']
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
