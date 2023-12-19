control 'SV-243499' do
  title 'Active Directory implementation information must be added to the organization contingency plan where the Risk Management Framework categorization for Availability is moderate or high.'
  desc 'When an incident occurs that requires multiple Active Directory (AD) domain controllers to be rebuilt, it is critical to understand the AD hierarchy and replication flow so that the correct recovery sequence and configuration values can be selected.  Without appropriate AD forest, tree and domain structural documentation, it may be impossible or very time consuming to reconstruct the original configuration.'
  desc 'check', "Determine the Availability categorization information for the domain.
If the Availability categorization of the domain is low, this is NA.
If the Availability categorization of the domain is moderate or high, verify the organization's disaster recovery plans includes documentation on the AD hierarchy (forest, tree and domain structure).
 (A chart showing forest hierarchy and domain names is the minimum suggested.)

If the disaster recovery plans do not include directory hierarchy information, this is a finding."
  desc 'fix', 'Update the disaster recovery plans to include the AD hierarchy structure for domains with an Availability categorization of moderate or high.'
  impact 0.3
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46774r723530_chk'
  tag severity: 'low'
  tag gid: 'V-243499'
  tag rid: 'SV-243499r723532_rule'
  tag stig_id: 'DS00.6120_AD'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46731r723531_fix'
  tag 'documentable'
  tag legacy: ['V-8525', 'SV-30995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
