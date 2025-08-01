control 'SV-243496' do
  title 'Accounts from outside directories that are not part of the same organization or are not subject to the same security policies must be removed from all highly privileged groups.'
  desc 'Membership in certain default directory groups assigns a high privilege level for access to the directory. In AD, membership in the following groups enables high privileges relative to AD and the Windows OS: Domain Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners, and Incoming Forest Trust Builders. 

When accounts from an outside directory are members of highly privileged groups in the directory being reviewed, less rigorous security policies or compromises of accounts in the outside directory could increase the risk to the directory where the privileged groups are defined. A compromise to the outside directory would allow unauthorized, privileged access.'
  desc 'check', '1. Start the Active Directory Users and Computers console (Start, Run, "dsa.msc").

2. Select and expand the left pane item that matches the name of the domain being reviewed.

3. Select the Built-in container. 
a. If the Incoming Forest Trust Builders group is defined, double-click on the group, and select the Members tab
b. Examine the defined accounts to see if they are from a domain that is not in the forest being reviewed.

4. Select the Users container
a. For each group (Domain Admins, Enterprise Admins, Schema Admins, and Group Policy Creator Owners), double-click on the group, and select the Members tab.
b. Examine the defined accounts to see if they are from a domain that is not in the forest being reviewed.

5. If any account in a privileged group is from a domain outside the forest being reviewed and that outside forest is not maintained by the same organization (e.g., enclave) or subject to the same security policies, then this is a finding.

Supplementary Notes:
Note: An account that is from an outside domain appears in the format "outside-domain-NetBIOSname\\account" or "account@outside-domain-fully-qualified-name". Examples are "AOFN21\\jsmit" or "jsmith@AOFN21.OST.COM". It may be necessary to use the AD Domains and Trusts (domain.msc) console to determine if the domain is from another AD forest.

Note:  It is possible to move the highly privileged AD security groups out of the AD Users container. If the Domain Admins, Enterprise Admins, Schema Admins, or Group Policy Creator Owners groups are not in the AD Users container, ask the SA for the new location and use that location for this check.'
  desc 'fix', 'Remove accounts from outside directories that are not part of the same organization or are not subject to the same security policies from the highly privileged groups.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46771r804647_chk'
  tag severity: 'medium'
  tag gid: 'V-243496'
  tag rid: 'SV-243496r804648_rule'
  tag stig_id: 'DS00.3200_AD'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46728r723522_fix'
  tag 'documentable'
  tag legacy: ['V-8549', 'SV-31557']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
