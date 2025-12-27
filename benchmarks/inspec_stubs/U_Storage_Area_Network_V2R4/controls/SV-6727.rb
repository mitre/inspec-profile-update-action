control 'SV-6727' do
  title 'Hard zoning is not used to protect the SAN.'
  desc %q(Risk:  In a SAN environment, we potentially have data with differing levels or need-to-know stored on the same "system".  A high level of assurance that a valid entity (user/system/process) of one set of data is not inadvertently given access to data that is unauthorized. Depending on the data and implementation, lack of hard zoning could provide access to classifed, administrative configuration, or other privileged information.

A zone is considered to be "hard" if it is hardware enforced.  In other words, it is considered “hard” in that they are always enforced by the destination ASIC. "Soft" zoning is more flexible but is also more vulnerable.    

In "soft" or WWN-enforced zoning, however, the HBA on the initiating devices store a copy of the name server entries, which were discovered in the last IO scan/discovery. It is possible for the HBA to include old addresses, which are no longer allowed in the newly established zoning rules. So your goal is to mitigate this risk in some way.

If hardware enforced zoning is used this is not an issue as the destination port will not allow any access regardless of what the OS/HBA “thinks” it has access to. 

Supplementary Note: Registry State Change Notifications ( RSCN ) storms in large SAN deployments are another factor of which the system administrator must be aware. RSCNs are a broadcast function that allows notification to registered devices when a state change occurs within a SAN topology. These changes could be as simple as a cable being unplugged or a new HBA being connected. When such changes take place, all members would have to be notified of the change and conflicts would have to be resolved, before the name servers are updated. In large configurations it could take a long time for the entire system to stabilize, impairing performance. Effective zoning on the switch would help in minimizing RSCN storms, as only devices within a zone would get notified of state changes. It would also be ideal to make note of business critical servers and make changes to zones and fabrics that affect these servers at non business critical times. Tape fabrics could also be separated from disk fabric (although this comes at a cost). Statistics of RSCN's are available from a few switch vendors. Monitoring these consistently and considering these before expansion of SAN's would help you with effective storage deployments.)
  desc 'check', 'The reviewer, with the assistance of the IAO/NSO, will verify that hard zoning is used to protect the SAN.

If soft zoning is used, this is a finding.  If soft zoning must be used (with DAA approval), this is still a CAT II finding and a migration plan must be in place.  However, note that the HBA’s memory is non-persistent, thus when zoning changes are made, a policy must be in place (show via the log that it is enforced) to force a state change update in the affected HBAs immediately after making zoning changes.'
  desc 'fix', 'If zoning has not been implemented, develop a zone topography.  From the topography, create a plan to implement hard zoning, obtain CM approval of the plan and then, following the plan, reconfigure the SAN to support hard zoning.

If zoning has been implemented, develop a plan to migrate to hard zoning, obtain CM approval of the plan and then, following the plan, reconfigure the SAN to support hard zoning.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2436r1_chk'
  tag severity: 'high'
  tag gid: 'V-6608'
  tag rid: 'SV-6727r1_rule'
  tag stig_id: 'SAN03.002.00'
  tag gtitle: 'Hard zoning is not used to protect the SAN.'
  tag fix_id: 'F-6195r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Although soft zoning is not recommended for DoD SAN implementations, this form of zoning does partially mitigate the risk and is preferred to no zoning. If soft zoning is used AND the system is does not process classified information, then this finding may be downgraded to a CAT 2 with a
POA&M documenting a migration plan for implementation of hard zoning.'
  tag potential_impacts: 'If the zoning ACLs are not properly migrated from the soft zoning format to the hard zoning format a denial of service can be created where a client is not allowed to access required data.  Also a compromise of sensitive data can occur if a client is allowed access to data not required.  This can also happen if you are moving from no zoning to hard zoning and incorrectly configure the ACLs.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
