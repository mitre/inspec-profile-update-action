control 'SV-253094' do
  title 'YUM must remove all software components after updated versions have been installed on TOSS.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify the operating system removes all software components after updated versions have been installed.

Check if YUM is configured to remove unneeded packages with the following command:

$ sudo grep -i clean_requirements_on_remove /etc/dnf/dnf.conf

clean_requirements_on_remove=True

If "clean_requirements_on_remove" is not set to either "1", "True", or "yes", commented out, or is missing from "/etc/dnf/dnf.conf", this is a finding.'
  desc 'fix', 'Configure the operating system to remove all software components after updated versions have been installed.

Set the "clean_requirements_on_remove" option to "True" in the "/etc/dnf/dnf.conf" file:

clean_requirements_on_remove=True'
  impact 0.3
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56547r824952_chk'
  tag severity: 'low'
  tag gid: 'V-253094'
  tag rid: 'SV-253094r824954_rule'
  tag stig_id: 'TOSS-04-040500'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-56497r824953_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
