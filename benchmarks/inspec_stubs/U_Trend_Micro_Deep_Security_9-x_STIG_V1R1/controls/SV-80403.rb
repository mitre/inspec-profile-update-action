control 'SV-80403' do
  title 'Trend Deep Security must ensure users are authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, application users must be individually identified and authenticated. 

Individual accountability mandates that each user is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the application using a single account. 

If an application allows or provides for group authenticators, it must first individually authenticate users prior to implementing group authenticator functionality. 

Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a group authenticator, this requirement will apply.

There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information.'
  desc 'check', 'Review the Trend Deep Security server to ensure users are authenticated with an individual authenticator prior to using a group authenticator.

Review the settings to ensure identify management is being performed through the organizations Active Directory. 

Navigate to Administration >> User Management >> Users and click "Synchronize with Directory".

Select "Re-Synchronize (Using previous settings)", and click "Next".

If the synchronization fails, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to authenticate users with an individual authenticator prior to using a group authenticator.

Navigate to Administration >> User Management >> Users and click "Synchronize with Directory".

Under Server, enter the following information:

Server Address (IP of the AD Server) 
Access Method (UserID/Password StartTLS)
UserName (Authorized, site-defined, service account used for synchronizing with Trend Deep Security)
Password

Click "Next".

Select the authorized AD group used for managing the Trend Deep Security accounts, and Click "Next".

Under "New User" Options, select the appropriate Role, click "Next".

Click "Finish".'
  impact 0.7
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66561r2_chk'
  tag severity: 'high'
  tag gid: 'V-65913'
  tag rid: 'SV-80403r1_rule'
  tag stig_id: 'TMDS-00-006030'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-71989r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
