control 'SV-83771' do
  title 'The NSX Manager must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 
 
Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Verify NSX Manager does not have the default manufacturer password.

Log into NSX Manager with built-in administrator account "admin" with the default manufacturer password "default".

If the NSX Manager accepts the default manufacturer password, this is a finding.'
  desc 'fix', 'Change the NSX Manager default manufacturer password.

Log into NSX Manager with built-in administrator account "admin" and the default manufacturer password "default".

Type "configure terminal", hit enter >> type "cli password" [enter new password], hit enter >> type "exit" >> type "exit".'
  impact 0.7
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69605r1_chk'
  tag severity: 'high'
  tag gid: 'V-69167'
  tag rid: 'SV-83771r1_rule'
  tag stig_id: 'VNSX-ND-000022'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-75353r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
