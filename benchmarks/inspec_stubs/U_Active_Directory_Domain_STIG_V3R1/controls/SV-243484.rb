control 'SV-243484' do
  title 'Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust.'
  desc 'Under some circumstances it is possible for attackers or rogue administrators that have compromised a domain controller in a trusted domain to use the SID history attribute (sIDHistory) to associate SIDs with new user accounts, granting themselves unauthorized rights.  To help prevent this type of attack, SID filter quarantining is enabled by default on all external trusts.   However, it is possible for an administrator to change this setting or the trust may have been created in an older version of AD. 

 SID filtering causes SID references that do not refer to the directly trusted domain or forest to be removed from inbound access requests in the trusting domain.  Without SID filtering, access requests could contain spoofed SIDs, permitting unauthorized access.  

In cases where access depends on SID history or Universal Groups, failure to enable SID filtering could result in operational problems, including denial of access to authorized users.

When the quarantine switch is applied to external or forest trusts, only those SIDs from the single, directly trusted domain are valid.  In effect, enabling /quarantine on a trust relationship will break the transitivity of that trust so that only the specific domains on either side of the trust are considered participants in the trust.'
  desc 'check', 'Open "Active Directory Domains and Trusts". (Available from various menus or run "domain.msc".)
Right click the domain in the left pane and select Properties.
Select the Trusts tab.
Note any existing trusts and the type.
If no trusts exist, this is NA.

If the trust type is External, run the following command on the trusting domain:
"netdom trust <trusting domain> /d:<trusted domain> /quarantine"
If the result does not specify "SID filtering is enabled for this trust.  Only SIDs from the trusted domain will be accepted for authorization data returned during authentication.  SIDs from other domains will be removed.", this is a finding. 

If the trust type is Forest, run the following command on the trusting domain:
"netdom trust <trusting domain> /d:<trusted domain> /enablesidhistory"
If the result does not specify "SID history is disabled for this trust", this is a finding.'
  desc 'fix', 'Ensure SID filtering is enabled on all external trusts.  You can enable SID filtering only from the trusting side of the trust.  Enter the following line from a command line:

netdom trust <TrustingDomainName> /d:<TrustedDomainName> /quarantine:Yes
/usero:<DomainAdministratorAcct> /passwordo:<DomainAdminPwd>

Ensure SID history is disabled for all forest trusts.  You can disable SID history only from the trusting side of the trust.  Enter the following line from a command line:

netdom trust <TrustingDomainName> /d:<TrustedDomainName> /enablesidhistory:No
/usero:<DomainAdministratorAcct> /passwordo:<DomainAdminPwd>'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46759r723485_chk'
  tag severity: 'medium'
  tag gid: 'V-243484'
  tag rid: 'SV-243484r723487_rule'
  tag stig_id: 'AD.0190'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-46716r723486_fix'
  tag 'documentable'
  tag legacy: ['V-8538', 'SV-9035']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
