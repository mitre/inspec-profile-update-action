control 'SV-252189' do
  title 'The HPE Nimble must not have any default manufacturer passwords when deployed.'
  desc 'Network devices not protected with strong password schemes provide the opportunity for anyone to crack the password and gain access to the device, which can result in loss of availability, confidentiality, or integrity of network traffic. 

Many default vendor passwords are well known or are easily guessed; therefore, not removing them prior to deploying the network device into production provides an opportunity for a malicious user to gain unauthorized access to the device.'
  desc 'check', 'Attempt to login using SSH to a configured array using username "admin" and password "admin". If the login is successful, this is a finding.'
  desc 'fix', 'On an unconfigured array, the setup command requires the "--password <new password>" argument to be supplied. To fix an already configured array: after logging into the array as the "admin" user, type "useradmin --passwd", and enter the old and new passwords.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55645r814045_chk'
  tag severity: 'medium'
  tag gid: 'V-252189'
  tag rid: 'SV-252189r814047_rule'
  tag stig_id: 'HPEN-NM-000040'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-55595r814046_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
