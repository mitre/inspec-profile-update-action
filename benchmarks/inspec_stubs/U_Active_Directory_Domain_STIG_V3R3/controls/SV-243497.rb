control 'SV-243497' do
  title 'Inter-site replication must be enabled and configured to occur at least daily.'
  desc 'Timely replication makes certain that directory service data is consistent across all servers that support the same scope of data for their clients. In AD implementation using AD Sites, domain controllers defined to be in different AD Sites require Site links to specify properties for replication scheduling.

If AD Site link schedule and replication interval properties are configured improperly, AD data replication may not occur frequently enough and updates to identification, authentication, or authorization data may not be current on all domain controllers. If this data is not current, access to resources may be incorrectly granted or denied. The default for inter-site replication is to occur every 180 minutes, 24 hours a day.'
  desc 'check', 'Open "Active Directory Sites and Services".  (Available from various menus or run "dssite.msc".)
Expand "Sites" in the left pane.
If only a single site exists, this is NA.  By default the first site in a domain is named "Default-First-Site-Name" but may have been changed.
If more than one site exists, expand "Inter-Site Transports" and select "IP".
For each site link that is defined in the right pane perform the following:
Right click the site link item and select "Properties".

If the interval on the "General" tab for the "Replicate every" field is greater than "1440", this is a finding.

Click the "Change Schedule" button.

If the time frames selected for "Replication Available" do not allow for replication to occur at least daily, this is a finding.

Click the Cancel buttons to exit.'
  desc 'fix', 'Maintain an Active Directory replication schedule that allows inter-site replication to occur at least on a daily basis.
Open "Active Directory Sites and Services". (Available from various menus or run "dssite.msc".)
Expand "Sites" in the left pane.
Expand "Inter-Site Transports" and select "IP".
For each site link that is defined in the right pane perform the following:
Right click the site link item and select "Properties".	
Select an interval in the "Replicate every" field less than "1440".  (By default this is 180.)
Click the Change Schedule button.
Select time frames for "Replication Available" to allow for replication to occur at least daily.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46772r723524_chk'
  tag severity: 'medium'
  tag gid: 'V-243497'
  tag rid: 'SV-243497r723526_rule'
  tag stig_id: 'DS00.3230_AD'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46729r723525_fix'
  tag 'documentable'
  tag legacy: ['V-8553', 'SV-30992']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
