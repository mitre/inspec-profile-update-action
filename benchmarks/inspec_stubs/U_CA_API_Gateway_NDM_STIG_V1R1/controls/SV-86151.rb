control 'SV-86151' do
  title 'The CA API Gateway must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Verify login as "root" (at the console) and "ssgconfig" have non-default passwords. 

The default password for "root" is "7layer" and the default password for "ssgconfig" is "7layer".

If root or ssgconfig use default passwords, this is a finding.'
  desc 'fix', 'Use the "passwd" command to set non-default passwords.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71527'
  tag rid: 'SV-86151r1_rule'
  tag stig_id: 'CAGW-DM-000140'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-77847r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
