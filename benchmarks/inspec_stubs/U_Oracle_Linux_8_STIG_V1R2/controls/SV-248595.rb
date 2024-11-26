control 'SV-248595' do
  title 'YUM must remove all software components after updated versions have been installed on OL 8.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify the operating system removes all software components after updated versions have been installed. 
 
Check if YUM is configured to remove unneeded packages with the following command: 
 
$ sudo grep -i clean_requirements_on_remove /etc/yum.conf 
 
clean_requirements_on_remove=True 
 
If "clean_requirements_on_remove" is not set to "True", commented out, or missing from "/etc/yum.conf", this is a finding.'
  desc 'fix', 'Configure OL 8 to remove all software components after updated versions have been installed. 
 
Set the "clean_requirements_on_remove" option to "True" in the "/etc/yum.conf" file: 
 
clean_requirements_on_remove=True'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52029r779349_chk'
  tag severity: 'low'
  tag gid: 'V-248595'
  tag rid: 'SV-248595r779351_rule'
  tag stig_id: 'OL08-00-010440'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-51983r779350_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
