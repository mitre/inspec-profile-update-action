control 'SRG-OS-000001-CLD-000010_rule' do
  title 'The Mission Owner must configure the customer portal credentials for least privilege.'
  desc 'Specific individuals or entities must explicitly be appointed by the DOD Mission Owner to establish plans and policies for the control of privileged user access (to include root account credentials) used to establish, configure, and control a Mission Owner’s Virtual Private Cloud (VPC) configuration once connected to the DISN. These individuals or entities establish and manage Least-Privilege Attribute-Based Access Control (ABAC) accounts and credentials used by privileged DOD users and systems to administer and control DOD cloud service offering configurations. 

This role is intended to operate at all DOD information Impact Levels. However, it may not apply to some SaaS solutions where DOD account owners are not required to use the CSP’s Identity and Access Management (IdAM) system to administer user accounts and service configurations.'
  desc 'check', "Review the site's approval documentation to ensure an individual or entity has been appointed to manage the cloud management service portal. This may be a group or contracted service. Verify the cloud service offering has been configured to allow only these individuals for portal service and virtual instance configuration.

If the Mission Owner has not configured the customer portal credentials and the Mission Owner application/system privileged accounts for least privilege, this is a finding."
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Appoint an individual or entity to manage portal services. Application and enclave administrators should also be appointed. Configure access for these individuals to access and configure services and virtual instances.'
  impact 0.7
  tag check_id: 'C-SRG-OS-000001-CLD-000010_chk'
  tag severity: 'high'
  tag gid: 'SRG-OS-000001-CLD-000010'
  tag rid: 'SRG-OS-000001-CLD-000010_rule'
  tag stig_id: 'SRG-OS-000001-CLD-000010'
  tag gtitle: 'SRG-OS-000001-CLD-000010'
  tag fix_id: 'F-SRG-OS-000001-CLD-000010_fix'
  tag 'documentable'
  tag cci: ['CCI-000015', 'CCI-000038']
  tag nist: ['AC-2 (1)', 'AC-6 (1)']
end
