control 'SV-74825' do
  title 'Google Search Appliances providing remote access capabilities must utilize approved cryptography to protect the confidentiality of remote access sessions.'
  desc 'Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization-controlled network (e.g., the Internet). Examples of remote access methods include dial-up, broadband, and wireless.  

Remote network access is accomplished by leveraging common communication protocols and establishing a remote connection.  These connections will typically occur over either the public Internet or the Public Switched Telephone Network (PSTN).  Since neither of these internetworking mechanisms are private nor secure, if cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised.  Cryptography provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information traversing the remote connection.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Log on to the GSA management interface.

Click Administration >> Remote Support.

If "Enable SSH for Remote Support" is unchecked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Click Administration >> Remote Support.

Uncheck the option "Enable SSH for Remote Support".

Click Update.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61359r2_chk'
  tag severity: 'medium'
  tag gid: 'V-60395'
  tag rid: 'SV-74825r1_rule'
  tag stig_id: 'GSAP-00-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-66053r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
