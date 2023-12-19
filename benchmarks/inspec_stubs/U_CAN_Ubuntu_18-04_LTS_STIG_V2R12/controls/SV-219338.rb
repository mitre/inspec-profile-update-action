control 'SV-219338' do
  title 'The Ubuntu operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the Ubuntu operating system. Changes to Ubuntu operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the Ubuntu operating system. The Ubuntu operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

"
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered.

Check that AIDE notifies the system administrator when anomalies in the operation of any security functions are discovered with the following command:

#sudo grep SILENTREPORTS /etc/default/aide

SILENTREPORTS=no

If SILENTREPORTS is uncommented and set to yes, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner.

Modify the "SILENTREPORTS" parameter in the "/etc/default/aide" file with a value of "no" if it does not already exist.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21063r305342_chk'
  tag severity: 'medium'
  tag gid: 'V-219338'
  tag rid: 'SV-219338r853397_rule'
  tag stig_id: 'UBTU-18-010508'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-21062r305343_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag legacy: ['SV-110003', 'V-100899']
  tag cci: ['CCI-001744', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 d']
end
