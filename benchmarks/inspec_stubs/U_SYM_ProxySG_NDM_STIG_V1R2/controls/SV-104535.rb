control 'SV-104535' do
  title 'Symantec ProxySG must not have a default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Verify the initial configuration has been set. Attempt to logon to an SSH session using the default user name of "Admin". Verify that there is a prompt for a password.

If Symantec ProxySG does not prompt for a password when logon is attempted, this is a finding.'
  desc 'fix', 'Passwords are set during initial configuration of the Symantec ProxySG. In order to perform this action on a new appliance:

1. Connect to the Symantec ProxySG via a serial console, choose "Manual Setup", and follow the prompts to set system parameters, including local account passwords. 
2. Once the system has been configured, local passwords can be changed from the Web Management Console, click Configuration >> Authentication >> Console Access >> Change Password.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94705'
  tag rid: 'SV-104535r1_rule'
  tag stig_id: 'SYMP-NM-000270'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-100823r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
