control 'SV-221697' do
  title 'The Oracle Linux operating system must not allow a non-certificate trusted host SSH logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.

Check for the value of the "HostbasedAuthentication" keyword with the following command:

# grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system not to allow a non-certificate trusted host SSH logon to the system.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "HostbasedAuthentication" keyword and set the value to "no":

HostbasedAuthentication no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23412r419163_chk'
  tag severity: 'medium'
  tag gid: 'V-221697'
  tag rid: 'SV-221697r603260_rule'
  tag stig_id: 'OL07-00-010470'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-23401r419164_fix'
  tag 'documentable'
  tag legacy: ['V-99133', 'SV-108237']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
