control 'SV-221706' do
  title 'The Oracle Linux operating system must implement the Endpoint Security for Linux Threat Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to take actions automatically in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime.

"
  desc 'check', 'Per OPORD 16-0080, the preferred intrusion detection system is McAfee Endpoint Security for Linux (ENSL) in conjunction with SELinux.
 
Procedure:
Check that the following package has been installed:

# rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

# ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23421r754734_chk'
  tag severity: 'medium'
  tag gid: 'V-221706'
  tag rid: 'SV-221706r754736_rule'
  tag stig_id: 'OL07-00-020019'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-23410r754735_fix'
  tag satisfies: ['SRG-OS-000191-GPOS-00080', 'SRG-OS-000196']
  tag 'documentable'
  tag legacy: ['SV-108255', 'V-99151']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
