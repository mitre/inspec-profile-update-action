control 'SV-202026' do
  title 'The network device must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Review the configuration of the network device to determine if the vendor default password is present. This may involve showing the passwords configured on the device in the clear.'
  desc 'fix', 'Remove any vendor default passwords from the network device configuration.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2152r381599_chk'
  tag severity: 'medium'
  tag gid: 'V-202026'
  tag rid: 'SV-202026r879554_rule'
  tag stig_id: 'SRG-APP-000080-NDM-000345'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-2153r381600_fix'
  tag 'documentable'
  tag legacy: ['SV-78487', 'V-63997']
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
