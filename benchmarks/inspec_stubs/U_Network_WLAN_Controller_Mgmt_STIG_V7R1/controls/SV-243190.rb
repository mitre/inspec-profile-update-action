control 'SV-243190' do
  title 'The network device must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Review the network device configuration to determine if the vendor default password is active.

If any vendor default passwords are used on the device, this is a finding.'
  desc 'fix', 'Remove any vendor default passwords from the network device configuration.'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46465r720023_chk'
  tag severity: 'medium'
  tag gid: 'V-243190'
  tag rid: 'SV-243190r720025_rule'
  tag stig_id: 'WLAN-ND-000300'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-46422r720024_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
