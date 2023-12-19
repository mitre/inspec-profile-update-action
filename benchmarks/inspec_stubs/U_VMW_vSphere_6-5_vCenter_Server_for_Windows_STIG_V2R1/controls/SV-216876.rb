control 'SV-216876' do
  title 'The vCenter Server for Windows must enable TLS 1.2 exclusively.'
  desc 'TLS 1.0 and 1.1 are deprecated protocols with well published shortcomings and vulnerabilities. TLS 1.2 should be disabled on all interfaces and TLS 1.1 and 1.0 disabled where supported. Mandating TLS 1.2 may break third party integrations and add-ons to vSphere. Test these integrations carefully after implementing TLS 1.2 and roll back where appropriate. On interfaces where required functionality is broken with TLS 1.2 this finding is N/A until such time as the third party software supports TLS 1.2.

Make sure you modify TLS settings in the following order: 1. Platform Services Controls (if applicable), 2. vCenter, 3. ESXi'
  desc 'check', 'Download the VMware TLS Reconfigurator utility from my.vmware.com. Follow installation instructions for your vCenter platform according to VMware KB 2147469.

Appliance:
1. /usr/lib/vmware-vSphereTlsReconfigurator/VcTlsReconfigurator/reconfigureVc backup
2. /usr/lib/vmware-vSphereTlsReconfigurator/VcTlsReconfigurator/reconfigureVc scan

Windows:
1. Open a command prompt and cd to C:\\Program Files\\VMware\\CIS\\vSphereTlsReconfigurator\\VcTlsReconfigurator
2. Enter command "reconfigureVc scan" and press "Enter"

If the output indicates versions of TLS other than 1.2 are enabled, this is a finding.'
  desc 'fix', 'Download the VMware TLS Reconfigurator utility from my.vmware.com. Follow installation instructions for your vCenter platform according to VMware KB 2147469. Run the following commands.

Appliance:
1. /usr/lib/vmware-vSphereTlsReconfigurator/VcTlsReconfigurator/reconfigureVc backup
2. /usr/lib/vmware-vSphereTlsReconfigurator/VcTlsReconfigurator/reconfigureVc update -p TLS1.2

Windows:
1. Open a command prompt and cd to C:\\Program Files\\VMware\\CIS\\vSphereTlsReconfigurator\\VcTlsReconfigurator
2. Enter command "reconfigureVc backup" and press "Enter"
3. Enter command "reconfigureVc update -p TLS1.2" and press "Enter"

vCenter services will be restarted as part of the reconfiguration, the OS will not be restarted. You can add the --no-restart flag to restart services at a later time. Changes will not take effect until all services are restarted or the machine is rebooted.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18107r366342_chk'
  tag severity: 'medium'
  tag gid: 'V-216876'
  tag rid: 'SV-216876r612237_rule'
  tag stig_id: 'VCWN-65-000057'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18105r366343_fix'
  tag 'documentable'
  tag legacy: ['V-94817', 'SV-104647']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
