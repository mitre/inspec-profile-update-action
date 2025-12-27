control 'SV-246933' do
  title 'ONTAP must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'Audit records are stored on staging volumes when auditing is enabled. If the staging volumes do not exist when auditing is enabled, the auditing subsystem creates the staging volumes. These volumes hold the audit logs until they can be consolidated.

Enabling auditing will also enable guaranteed auditing by default. This feature will guarantee audit records are not lost even when a node goes offline or the disk becomes filled.
Audit records are stored on staging volumes prior to consolidation and conversion.

Staging volumes can only be created by ONTAP and are given volume names that begin with MDV_aud_ followed by the UUID of the aggregate containing the staging volume.'
  desc 'check', 'To ensure audit record storage capacity is sufficient, use the command "df MDV*".  The output from the command will show the size of the audit volumes, amount used and amount available.  Sample output from the command looks like the following:

cluster ::> df MDV*

Filesystem                                                                                            kbytes       used      avail           capacity        Mounted on
/vol/MDV_aud_4a9d8065eac9454bbe042ffddd0df645/    1992296        532      1991764             0%         /vol/MDV_aud_4a9d8065eac9454bbe042ffddd0df645/
/vol/MDV_aud_62a9aebc8f3d4fe2990e39bb34c66999/    1992296        384      1991912              0%        /vol/MDV_aud_62a9aebc8f3d4fe2990e39bb34c66999/
/vol/MDV_aud_fdb78598bd5945ffa6f7bd1197a9f975/      1992296    1992296              0           100%      /vol/MDV_aud_fdb78598bd5945ffa6f7bd1197a9f975/ 

If any ONTAP volumes show 100 percent capacity, this is a finding.'
  desc 'fix', 'Increase the size of the volume that is filled using the command "vol size <volume name> <size increase>".  

To increase vol1 by 500MB, the command would be "vol size vol1 +500m".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50365r860675_chk'
  tag severity: 'medium'
  tag gid: 'V-246933'
  tag rid: 'SV-246933r877997_rule'
  tag stig_id: 'NAOT-AU-000001'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-50319r860676_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
