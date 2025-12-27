control 'SV-243444' do
  title 'Administrative accounts of all high-value IT resources must be assigned to a specific administrative tier in Active Directory to separate highly privileged administrative accounts from less privileged administrative accounts.'
  desc 'Note: The Microsoft Tier 0-2 AD administrative tier model (https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ADATM_BM) is an example.

A key security construct of a PAW is to separate administrative accounts into specific trust levels so that an administrator account used to manage an IT resource at one trust level cannot be used to manage IT resources at another trust level. This architecture protects IT resources in a tier from threats from higher-risk tiers. Isolating administrative accounts by forcing them to operate only within their assigned trust zone implements the concept of containment of security risks and adversaries within a specific zone. The Tier model prevents escalation of privilege by restricting what administrators can control and where they can log on.'
  desc 'check', 'In Active Directory, verify an Organizational Unit (OU) and Group hierarchy have been set up to segregate administrative accounts used to manage both high-value IT resources and PAWs into assigned tiers.

Verify each administrative account and each PAW has been assigned to one and only one tier.

If the site has not set up a tier structure on Active Directory for administrative accounts used to manage either high-value IT resources or PAWs, this is a finding.

If any administrative account used to manage either high-value IT resources or PAWs is assigned to more than one tier, this is a finding.

If each administrative account and each PAW has not been assigned to one and only one tier, this is a finding.'
  desc 'fix', 'Set up an administrative tier model for the domain (for example, the Microsoft recommended Tier 0-2 AD administrative tier model).

Note: Details of the Tier model are found at https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material#ADATM_BM.

Set up an Admin Organizational Unit (OU) Framework to host site PAWs. (Recommend the Microsoft PAW scripts be used to set up the PAW OU and group framework. They can be downloaded at http://aka.ms/PAWmedia.)

For example:

- Admin\\Tier 0\\Accounts
- Admin\\Tier 1\\Accounts
- Admin\\Tier 2\\Accounts
- Admin\\Tier 0\\Groups
- Admin\\Tier 1\\Groups
- Admin\\Tier 2\\Groups
- Admin\\Tier 0\\Devices
- Admin\\Tier 1\\Devices
- Admin\\Tier 2\\Devices

Note: If using the Microsoft scripts, after running the scripts, PAW Users Tier 0, PAW Users Tier 1, and PAW Users Tier 2 groups may need to be created under Admin/Tier 0/Groups, Admin/Tier 1/Groups, and Admin/Tier 2/Groups, respectively. 

Set up administrative accounts for each assigned administrator for high-value IT resources.

Based on the list of high-value IT resources with assigned administrative tier level, move Tier 0-2 administrative accounts to the appropriate Organizational Units and add the appropriate members to the relevant groups. Make sure each account and group has been assigned to one and only one tier.

(Reference-defined groups in the Active Directory Domain STIG)'
  impact 0.5
  ref 'DPMS Target Windows PAW'
  tag check_id: 'C-46719r722901_chk'
  tag severity: 'medium'
  tag gid: 'V-243444'
  tag rid: 'SV-243444r722903_rule'
  tag stig_id: 'WPAW-00-000400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46676r722902_fix'
  tag 'documentable'
  tag legacy: ['V-78145', 'SV-92851']
  tag cci: ['CCI-000366', 'CCI-002227']
  tag nist: ['CM-6 b', 'AC-6 (5)']
end
