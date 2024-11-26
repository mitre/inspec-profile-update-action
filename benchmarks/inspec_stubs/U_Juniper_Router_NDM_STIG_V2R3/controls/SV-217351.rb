control 'SV-217351' do
  title 'The Juniper router must be configured to support organizational requirements to conduct backups of the configuration when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. The example configuration below will send the router configuration to an SCP server upon the commit command.

system {
…
…
…
    archival {
        configuration {
            transfer-on-commit;
            archive-sites {
                  "scp://scpuser@1.2.3.4:/configs" password "$9$CMJKpu1LX-bwgBIYo"; ## SECRET-DATA
            }
        }
    }
}

If the router is not configured to conduct backups of the configuration when changes occur, this is a finding.'
  desc 'fix', 'Configure the router to send the configuration to an SCP server up a commit command as shown in the example below.

set archival configuration transfer-on-commit archive-sites scp://scpuser@1.2.3.4:/configs" password "xxxxxxxx"'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18578r296631_chk'
  tag severity: 'medium'
  tag gid: 'V-217351'
  tag rid: 'SV-217351r916221_rule'
  tag stig_id: 'JUNI-ND-001400'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-18576r296632_fix'
  tag 'documentable'
  tag legacy: ['SV-101291', 'V-91191']
  tag cci: ['CCI-000537', 'CCI-000366']
  tag nist: ['CP-9 (b)', 'CM-6 b']
end
