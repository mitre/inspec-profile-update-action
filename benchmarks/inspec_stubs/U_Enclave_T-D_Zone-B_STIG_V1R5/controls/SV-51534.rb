control 'SV-51534' do
  title 'Remote access into the test and development environment must use an encryption mechanism approved for the classification level of the network.'
  desc "Remote access to the environment using unapproved encryption mechanism is inherently dangerous because anyone with a packet sniffer and access to the network can acquire the device's account and password information.  With this intercepted information, a malicious user could gain access to the device, cause denial of service attacks, intercept sensitive information, or perform other destructive actions."
  desc 'check', 'Determine whether the proper encryption standard is deployed for the classification of the network where remote access is performed.  Unclassified/FOUO or any need-to-know data will need to use a FIPS 140-2 validated cryptographic module.  Classified traffic must use an NSA approved encryption standard.  If the proper encryption standard is not in use for remote access, this is a finding.'
  desc 'fix', 'Implement an approved encryption mechanism for the classification of the network for remote access.  Unclassified/FOUO or any need-to-know data will need to use a FIPS 140-2 validated cryptographic module.  Classified traffic must use an NSA approved encryption standard.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46822r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39667'
  tag rid: 'SV-51534r1_rule'
  tag stig_id: 'ENTD0280'
  tag gtitle: 'ENTD0280 - An approved encryption mechanism is not used for remote access.'
  tag fix_id: 'F-44675r1_fix'
  tag 'documentable'
  tag ia_controls: 'EBRU-1, ECCT-1, ECCT-2'
end
