control 'SV-221715' do
  title 'The Oracle Linux operating system must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify the operating system removes all software components after updated versions have been installed.

Check if yum is configured to remove unneeded packages with the following command:

# grep -i clean_requirements_on_remove /etc/yum.conf
clean_requirements_on_remove=1

If "clean_requirements_on_remove" is not set to "1", "True", or "yes", or is not set in "/etc/yum.conf", this is a finding.'
  desc 'fix', 'Configure the operating system to remove all software components after updated versions have been installed.

Set the "clean_requirements_on_remove" option to "1" in the "/etc/yum.conf" file:

clean_requirements_on_remove=1'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23430r419217_chk'
  tag severity: 'low'
  tag gid: 'V-221715'
  tag rid: 'SV-221715r853674_rule'
  tag stig_id: 'OL07-00-020200'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-23419r419218_fix'
  tag 'documentable'
  tag legacy: ['V-99169', 'SV-108273']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
