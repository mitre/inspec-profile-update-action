control 'SV-16789' do
  title 'VMware tools are not used to update the ESX Server.'
  desc 'VMware uses three categories for patches: Security, Critical, and General. VMware will usually issue a KB article when they become aware of security vulnerabilities and other serious functionality issues before they issue a patch. Only VMware released patches and tools (such as esxupdate) should be implemented. Do not use RedHat or third party patches or tools such as yum or rpm to update the system because VMware has made modifications to the system and kernel.'
  desc 'check', 'On the ESX Server service console perform the following commands:
# grep esxupdate /var/log/vmware/esxupdate.log

If no entries are returned, this is a finding.'
  desc 'fix', 'Utilize VMware tools for all ESX Server updates.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16197r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15848'
  tag rid: 'SV-16789r1_rule'
  tag stig_id: 'ESX0490'
  tag gtitle: 'VMware tools are not used to update the ESX Server'
  tag fix_id: 'F-15802r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
end
