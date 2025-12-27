control 'SV-256904' do
  title 'Automation Controller must be capable of reverting to the last known good configuration in the event of failed installations and upgrades.'
  desc 'Any changes to the components of Automation Controller can have significant effects on the overall security of the system.

In order to ensure a prompt response to failed application installations and application server upgrades, Automation Controller must provide an automated rollback capability that allows Automation Controller to be restored to a previous known good configuration state prior to the application installation or application server upgrade.'
  desc 'check', 'The administrator must make a backup of the last known good configuration of the Automation Controller on each host.

Locate the installer bundle directory that contains the inventory file used to install Ansible Automation Platform.

Verify a backup of the last known good configuration has been made and stored in accordance with the Automation Controller Documentation and organizationally defined policy:
https://docs.ansible.com/automation-controller/latest/html/administration/backup_restore.html

If no such backup has been made, this is a finding.'
  desc 'fix', 'As System Administrator login to the Controller. Locate the installer bundle directory that contains the inventory file used to install Ansible Automation Platform. From there, run the setup.sh command with the "-b" option to perform a backup.
 Example: "[[installation directory]]/setup.sh -b"

Note: To revert from a backup, refer to:
https://docs.ansible.com/automation-controller/latest/html/administration/backup_restore.html'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60579r902280_chk'
  tag severity: 'medium'
  tag gid: 'V-256904'
  tag rid: 'SV-256904r902282_rule'
  tag stig_id: 'APAS-AT-000044'
  tag gtitle: 'SRG-APP-000133-AS-000093'
  tag fix_id: 'F-60521r902281_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
