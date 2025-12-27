control 'SV-246850' do
  title 'The HYCU server must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'HYCU is a VM that synchronizes time with the Nutanix or VMware platform as part of the maintenance task using the "chronyd" daemon.

To verify the service is synchronizing the NTP servers from Nutanix as part of maintenance task, log on to the HYCU console and edit the "/etc/chrony.conf" configuration file by executing the following command: 
sudo vi /etc/chrony.conf

Change the last line in the file showing the value of server variable to an incorrect IP and save the file (:wq!).

Trigger the maintenance task by restarting HYCU services with the following command:
sudo systemctl restart grizzly

If the value of the server variable inside the "/etc/chrony.conf" file is not fixed to match Nutanix NTP servers, this is a finding.'
  desc 'fix', 'Enable synchronization by logging on to the HYCU console and executing the following command:
sudo systemctl start chronyd'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50282r768212_chk'
  tag severity: 'medium'
  tag gid: 'V-246850'
  tag rid: 'SV-246850r768214_rule'
  tag stig_id: 'HYCU-IA-000002'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-50236r768213_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
