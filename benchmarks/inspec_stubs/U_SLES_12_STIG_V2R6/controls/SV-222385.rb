control 'SV-222385' do
  title 'The SUSE operating system must implement the Endpoint Security for Linux Threat Prevention tool.'
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
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18385r754752_chk'
  tag severity: 'medium'
  tag gid: 'V-222385'
  tag rid: 'SV-222385r754754_rule'
  tag stig_id: 'SLES-12-010599'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-36322r754753_fix'
  tag 'documentable'
  tag legacy: ['V-92249', 'SV-102351']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
