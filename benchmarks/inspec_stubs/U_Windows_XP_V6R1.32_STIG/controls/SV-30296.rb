control 'SV-30296' do
  title 'IPv6 will be disabled until a deliberate transition strategy has been implemented.'
  desc 'Any nodes’ interface with IPv6 enabled by default presents a potential risk of traffic being transmitted or received without proper risk mitigation strategy and therefore a serious security concern.'
  desc 'check', 'Prior to transition, IPv6 will not be installed.  The following registry key indicates the IPv6 protocol has been installed.  If it exists, then this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Services\\Tcpip6

Note:  The Gold Disk can only check for the existence of the key.  If IPv6 has been implemented in your environment, manually close the finding.

See S0-C1-imp-1 of the The Department of National Intelligence/Department of Defense (DoD) Internet Protocol version 6 (IPv6) Information Assurance Guidance for Milestone Objective 3 for additional information.'
  desc 'fix', 'Uninstall the IPv6 protocol until a deliberate transition strategy has been implemented.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-30789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14262'
  tag rid: 'SV-30296r1_rule'
  tag gtitle: 'IPv6 Transition'
  tag fix_id: 'F-27324r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
