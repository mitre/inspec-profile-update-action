control 'SV-82899' do
  title 'The Mainframe Product must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system. 

Non-organizational users include all information system users other than organizational users which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors and guest researchers). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine installation and configuration settings.

Examine user account configurations.

If the Mainframe Product does not uniquely identify and authenticate non-organizational users, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to uniquely identify and authenticate non-organizational users'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68941r3_chk'
  tag severity: 'medium'
  tag gid: 'V-68409'
  tag rid: 'SV-82899r1_rule'
  tag stig_id: 'SRG-APP-000180-MFP-000248'
  tag gtitle: 'SRG-APP-000180-MFP-000248'
  tag fix_id: 'F-74525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
