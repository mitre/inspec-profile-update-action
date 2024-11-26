control 'SV-230505' do
  title 'A firewall must be installed on RHEL 8.'
  desc '"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

RHEL 8 functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify that "firewalld" is installed with the following commands:

$ sudo yum list installed firewalld

firewalld.noarch     0.7.0-5.el8

If the "firewalld" package is not installed, ask the System Administrator if another firewall is installed. If no firewall is installed this is a finding.'
  desc 'fix', 'Install "firewalld" with the following command:

$ sudo yum install firewalld.noarch'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33174r744018_chk'
  tag severity: 'medium'
  tag gid: 'V-230505'
  tag rid: 'SV-230505r744020_rule'
  tag stig_id: 'RHEL-08-040100'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-33149r744019_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
