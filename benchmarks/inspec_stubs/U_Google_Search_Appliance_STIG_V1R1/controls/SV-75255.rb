control 'SV-75255' do
  title 'The Google Search Appliance must notify appropriate individuals when accounts are terminated.'
  desc 'When application accounts are terminated, user accessibility is affected.  Accounts are utilized for identifying individual application users or for identifying the application processes themselves. 

In order to detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals when an account is terminated so they can investigate the event.  Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes. 

To address the multitude of policy based audit requirements, and to ease the burden of meeting these requirements, many application developers choose to integrate their applications with enterprise level authentication/access/audit mechanisms that meet or exceed access control policy requirements. Examples include but are not limited to Active Directory and LDAP.

The application must automatically notify the appropriate individuals when accounts are terminated.'
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
  tag check_id: 'C-61727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60803'
  tag rid: 'SV-75255r1_rule'
  tag stig_id: 'GSAP-00-001040'
  tag gtitle: 'SRG-APP-000294'
  tag fix_id: 'F-66485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
