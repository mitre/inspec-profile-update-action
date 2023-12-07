control 'SV-214800' do
  title 'The Red Hat Enterprise Linux operating system must implement the Endpoint Security for Linux Threat Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred endpoint security tool is McAfee Endpoint Security for Linux (ENSL) in conjunction with SELinux. 

Procedure:
Check that the following package has been installed:

# rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

# ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-16000r754749_chk'
  tag severity: 'medium'
  tag gid: 'V-214800'
  tag rid: 'SV-214800r754751_rule'
  tag stig_id: 'RHEL-07-020019'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36317r754750_fix'
  tag 'documentable'
  tag legacy: ['V-92255', 'SV-102357']
  tag cci: ['CCI-001263']
  tag nist: ['SI-4 (5)']
end
