control 'SV-256076' do
  title 'The Riverbed NetProfiler must change the default admin credentials so they do not use the default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.

By default, NetProfiler provides a single user account and password: The user name is admin with a weak default password. This user account is assigned the built-in role of Administrator, which provides the admin user account with unrestricted access to all NetProfiler features and data.

At a minimum, change the default password to something less obvious and more complex. The default password is provided solely to enable logging in to the system and changing the configuration.'
  desc 'check', 'Attempt to log in to the NetProfiler web user interface using the default "admin" user account and password. 

Work with the site representative to verify the root and mazu passwords have been changed to DOD-compliant passwords and stored securely with limited access. 

If the admin, root, or mazu passwords have not been changed, this is a finding.'
  desc 'fix', 'Upon initial setup, log in to the NetProfiler web user interface using the "admin" user account and password. 

Wait until the configuration wizard starts and provide the required information at the prompts. Follow the wizard and change the default password when prompted.

Change default system shell account passwords as required. The appliance is shipped with shell access enabled:

Configuration >> Appliance Security >> Security Compliance page "Accounts" section

bootloader - The boot loader controls the image, and options are loaded with the operating system. There is no login access to this account. Password change is not required.

root - Accessible only through SSH from other modules in an Enterprise NetProfiler. This has shell access from the console if login is enabled. Change to implement a DOD-compliant password. Securely store and protect the password.

admin - Accessible only through the console port. This is for initial setup only; there is no shell access. Recommend use as account of last resort; however, login may be disabled only if another account of last resort is configured. Change to implement a DOD-compliant password. Securely store and protect the password.

mazu - Accessible through SSH. This has shell access unless disabled. Change to implement a DOD-compliant password. Securely store and protect the password.

dhcp - Accessible through SSH using keys.

support - DOD does not recommend enabling Challenge Mode because it requires a code from Riverbed Support.'
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59750r882734_chk'
  tag severity: 'high'
  tag gid: 'V-256076'
  tag rid: 'SV-256076r882736_rule'
  tag stig_id: 'RINP-DM-000011'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-59693r882735_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
