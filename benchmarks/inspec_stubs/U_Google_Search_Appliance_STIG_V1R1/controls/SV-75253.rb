control 'SV-75253' do
  title 'The Google Search Appliance must notify appropriate individuals when account disabling actions are taken.'
  desc 'When application accounts are disabled, user accessibility is affected.  Accounts are utilized for identifying individual application users or for identifying the application processes themselves. 

In order to detect and respond to events that affect user accessibility and application processing, applications must audit account disabling actions and, as required, notify as required the appropriate individuals so they can investigate the event.  Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.    

To address the multitude of policy based access requirements, many application developers choose to integrate their applications with enterprise level authentication/access mechanisms that meet or exceed access control policy requirements.  Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality. 

Examples of enterprise level authentication/access mechanisms include but are not limited to Active Directory and LDAP.

Applications must notify, or leverage other mechanisms that notify, the appropriate individuals when accounts disabling actions are taken.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Navigate to "Administration", select "System Settings".

If "Enable Daily Status Email Messages" is checked and a valid administrator email address is entered, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

Select "Enable Daily Status Email Messages" and enter a valid administrator email address.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61725r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60801'
  tag rid: 'SV-75253r1_rule'
  tag stig_id: 'GSAP-00-001035'
  tag gtitle: 'SRG-APP-000293'
  tag fix_id: 'F-66483r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001685']
  tag nist: ['AC-2 (4)']
end
