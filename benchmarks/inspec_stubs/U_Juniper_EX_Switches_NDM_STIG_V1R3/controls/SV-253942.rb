control 'SV-253942' do
  title 'The Juniper EX switch must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including firewall filters that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial-of-service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the network device configuration to determine if the device is configured to conduct backups of system-level information contained in the information system when changes occur. 

Verify the preferred centralized backup system is configured to retrieve the configuration file. There is no provision for backing up system binaries because Juniper provides the signed installation packages rather than individual files. Therefore, verify the centralized backup solution has the appropriate installation packages for the deployed platforms. 

When the configuration file is pulled from the centralized server, an example retrieval method is authenticated connections over NETCONF or manual retrieval using SSH. Junos supports authenticating external services via RADIUS or TACACS+, or via a local account.

[edit system services netconf]
ssh;
rfc-compliant;

If the network device will be saving system files to a centralized repository, verify the configuration file is automatically saved at each commit.

[edit system archival]
configuration {
    transfer-on-commit;
    archive-sites {
        "sftp://user@host/configuration_files" password "$9$w52...<snip>...mfzn/"; ## SECRET-DATA
    }
}
Note: The URL uses <scp|sftp>://<username>@<repository address>/<path without trailing slash (/)> format because Junos appends the slash with the system-generated filename. Junos supports file transfer either on commit, or at configured intervals.

If the network device is not configured to conduct backups of system-level data when changes occur, this is a finding.'
  desc 'fix', 'Configure the network device to conduct backups of system-level information contained in the information system when changes occur.

For NETCONF connections:
set system services netconf ssh
set system services netconf rfc-compliant

For device automated configuration offload:
set system archival configuration transfer-on-commit
set system archival configuration archive-sites "<scp|sftp>://<username>@<address>/<path without trailing slash (/)>" password "<PSK>"'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57394r843857_chk'
  tag severity: 'medium'
  tag gid: 'V-253942'
  tag rid: 'SV-253942r879887_rule'
  tag stig_id: 'JUEX-NM-000650'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-57345r843858_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
