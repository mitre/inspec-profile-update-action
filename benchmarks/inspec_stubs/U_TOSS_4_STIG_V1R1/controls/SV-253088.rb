control 'SV-253088' do
  title 'A firewall must be installed on TOSS.'
  desc '"Firewalld" provides an easy and effective way to block/limit remote access to the system via ports, services, and protocols.

Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

TOSS functionality (e.g., SSH) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify that "firewalld" is installed and active with the following commands:

$ sudo yum list installed firewalld

firewalld.noarch 0.9.3-7.el8

$ sudo systemctl is-active firewalld

active

If the "firewalld" package is not installed and "active", ask the System Administrator if another firewall is installed. If no firewall is installed and active this is a finding.'
  desc 'fix', 'Install "firewalld" and enable with the following commands:

$ sudo yum install firewalld.noarch

$ sudo systemctl enable firewalld'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56541r824934_chk'
  tag severity: 'medium'
  tag gid: 'V-253088'
  tag rid: 'SV-253088r824936_rule'
  tag stig_id: 'TOSS-04-040370'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-56491r824935_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
