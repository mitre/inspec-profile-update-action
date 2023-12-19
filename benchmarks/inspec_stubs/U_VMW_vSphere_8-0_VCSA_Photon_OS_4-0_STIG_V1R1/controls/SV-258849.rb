control 'SV-258849' do
  title 'The Photon operating system must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', %q(At the command line, run the following command:

# grep -i '^clean_requirements_on_remove' /etc/tdnf/tdnf.conf

Example result:

clean_requirements_on_remove=1

If "clean_requirements_on_remove" is not set to "true", "1", or "yes", this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/tdnf/tdnf.conf

Add or update the following line:

clean_requirements_on_remove=1'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62589r933606_chk'
  tag severity: 'medium'
  tag gid: 'V-258849'
  tag rid: 'SV-258849r933608_rule'
  tag stig_id: 'PHTN-40-000161'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-62498r933607_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
