control 'SV-75251' do
  title 'The Google Search Appliance must notify appropriate individuals when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, they often attempt to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply modify or copy an existing account.

Notification of account modification is one method and best practice for mitigating this risk. A comprehensive account management process will ensure that an audit trail which documents the modification of application user accounts and notifies administrators and/or application owners exists. Such a process greatly reduces the risk that accounts will be surreptitiously created or modified and provides logging that can be used for forensic purposes.

To address the multitude of policy based access requirements, many application developers choose to integrate their applications with enterprise level authentication/access mechanisms that meet or exceed access control policy requirements.  Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.

Examples of enterprise level authentication/access mechanisms include but are not limited to Active Directory and LDAP.

Applications must support the requirement to notify appropriate individuals when accounts are modified.'
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
  tag check_id: 'C-61723r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60799'
  tag rid: 'SV-75251r1_rule'
  tag stig_id: 'GSAP-00-001030'
  tag gtitle: 'SRG-APP-000292'
  tag fix_id: 'F-66481r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
