control 'SV-219156' do
  title 'The Ubuntu operating system must be configured so that Advance package Tool (APT) removes all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify Advance package Tool (APT) is configured to remove all software components after updated versions have been installed.

Check that APT is configured to remove all software components after updating with the following command:

# grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

If the "::Remove-Unused-Dependencies" and "::Remove-Unused-Kernel-Packages" parameters are not set to "true", or are missing, or are commented out, this is a finding.'
  desc 'fix', 'Configure APT to remove all software components after updated versions have been installed.

Add or updated the following options to the "/etc/apt/apt.conf.d/50unattended-upgrades" file:

Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20881r304796_chk'
  tag severity: 'medium'
  tag gid: 'V-219156'
  tag rid: 'SV-219156r853364_rule'
  tag stig_id: 'UBTU-18-010017'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-20880r304797_fix'
  tag 'documentable'
  tag legacy: ['SV-109641', 'V-100537']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
