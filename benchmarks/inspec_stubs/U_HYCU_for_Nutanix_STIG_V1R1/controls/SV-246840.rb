control 'SV-246840' do
  title 'The HYCU server must be configured to conduct backups of system-level information when changes occur and to offload audit records onto a different system or media.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial-of-service condition is possible for all who use this critical network component.

Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify that HYCU is backing itself up by logging on to the HYCU Web UI and checking the HYCU Controller widget at the HYCU Dashboard. 

If the message "Controller VM is not protected" is found and highlighted with orange, this is a finding.'
  desc 'fix', 'Log on to the HYCU Web UI, go to the "Virtual Machines" menu, and apply a backup policy to the HYCU Server to back it up. 

Any documentation/configuration files stored on the HYCU server will be backed up as a result.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50272r768182_chk'
  tag severity: 'medium'
  tag gid: 'V-246840'
  tag rid: 'SV-246840r768184_rule'
  tag stig_id: 'HYCU-AU-000017'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-50226r768183_fix'
  tag satisfies: ['SRG-APP-000515-NDM-000325', 'SRG-APP-000516-NDM-000340', 'SRG-APP-000516-NDM-000341']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537', 'CCI-000539', 'CCI-001851']
  tag nist: ['CM-6 b', 'CP-9 (b)', 'CP-9 (c)', 'AU-4 (1)']
end
