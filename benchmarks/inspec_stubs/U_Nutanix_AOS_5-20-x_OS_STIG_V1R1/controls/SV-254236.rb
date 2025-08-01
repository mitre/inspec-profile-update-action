control 'SV-254236' do
  title 'Nutanix AOS must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Confirm Nutanix AOS removes all software components after updated versions have been installed.

$ sudo grep -i clean_requirements_on_remove /etc/yum.conf
clean_requirements_on_remove=1

If "clean_requirements_on_remove" is not set to "1", "True", or "yes", or is not set in "/etc/yum.conf", this is a finding.'
  desc 'fix', 'Configure Yum settings to remove all software components after an updated version is installed by running the following command:

$ sudo salt-call state.sls security/CVM/yumCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57721r846794_chk'
  tag severity: 'medium'
  tag gid: 'V-254236'
  tag rid: 'SV-254236r846796_rule'
  tag stig_id: 'NUTX-OS-001600'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-57672r846795_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
