control 'SV-237428' do
  title 'The Microsoft SCOM administration console must only be installed on Management Servers and hardened Privileged Access Workstations.'
  desc "The Microsoft SCOM management servers are considered high value IT resources where compromise would cause a significant impact to the organization. The Operations Manager console contains APIs that an attacker can use to decrypt Run As accounts or install malicious management packs. If a SCOM console sits on a Tier 2 device, an attacker could use the administrator's alternate credentials to exploit SCOM. A Privileged Admin Workstation (PAW) device provides configuration and installation requirements for dedicated Windows workstations used exclusively for remote administrative management of designated high-value IT resources."
  desc 'check', 'If the SCOM console is installed on a Terminal Server within a dedicated hardened management forest, this check is Not Applicable.

If the console is installed on a general purpose device and the user is NOT a SCOM administrator, this is not a finding. Examples would be individuals in the Network Operations Center (NOC) who only respond to alerts.

From the SCOM Administrator(s) productivity workstation (i.e. it has internet, or office applications), check for the presence of the operations console. This can be done by clicking the windows button and typing "Operations" in the search bar. 

If the console is installed on a general purpose device and the user is NOT a SCOM administrator, this is not a finding. Examples would be individuals in the Network Operations Center (NOC) who only respond to alerts.

If the Operations console appears, this is a finding.'
  desc 'fix', 'Remove any SCOM consoles from productivity workstations.'
  impact 0.3
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40647r643928_chk'
  tag severity: 'low'
  tag gid: 'V-237428'
  tag rid: 'SV-237428r643930_rule'
  tag stig_id: 'SCOM-AC-000006'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40610r643929_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
