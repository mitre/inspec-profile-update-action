control 'SV-206431' do
  title 'The web server must encrypt user identifiers and passwords.'
  desc 'When data is written to digital media, such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise. User identities and passwords stored on the hard drive of the hosting hardware must be encrypted to protect the data from easily being discovered and used by an unauthorized user to access the hosted applications. The cryptographic libraries and functionality used to store and retrieve the user identifiers and passwords must be part of the web server.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the web server is authorizing and managing users.

If the web server is not authorizing and managing users, this is NA. 

If the web server is the user authenticator and manager, verify that stored user identifiers and passwords are being encrypted by the web server. If the user information is not being encrypted when stored, this is a finding.'
  desc 'fix', 'Configure the web server to encrypt the user identifiers and passwords when storing them on digital media.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6692r377885_chk'
  tag severity: 'medium'
  tag gid: 'V-206431'
  tag rid: 'SV-206431r855052_rule'
  tag stig_id: 'SRG-APP-000429-WSR-000113'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-6692r377886_fix'
  tag 'documentable'
  tag legacy: ['SV-70285', 'V-56031']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
