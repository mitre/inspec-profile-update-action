control 'SV-16815' do
  title 'VirtualCenter vpxuser has been modified.'
  desc 'The vpxuser is created when the ESX Server host is attached to VirtualCenter. It is not present on the ESX Server host unless the host is being managed through VirtualCenter. SAs will not change vpxuser and its default permissions. Modifying these permissions may create problems working with the ESX Server host through VirtualCenter.'
  desc 'check', 'On the ESX Server service console perform the following:
# grep vpx /etc/passwd 

Output should appear as follows:
vpxuser:x:500:100:Vmware VirtualCenter administration account: /home/vpxuser:/bin/false

#grep vpx /etc/shadow
Output should appear as follows:
vpxuser:(hash value)/:13995:1:360:14:::  (These numbers may be different based on the site)

If any of these files have been changed from the above values for the vpxuser, this is a finding.'
  desc 'fix', 'Do not modify the vpxuser account.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16238r1_chk'
  tag severity: 'high'
  tag gid: 'V-15874'
  tag rid: 'SV-16815r1_rule'
  tag stig_id: 'ESX0750'
  tag gtitle: 'VirtualCenter vpxuser has been modified.'
  tag fix_id: 'F-15834r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Server Administrator]', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
end
