control 'SV-253937' do
  title 'The Juniper EX switch must be configured to offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the network device configuration to determine if the device offloads audit records onto a different system or media than the system being audited.

Verify the device is configured to send system events to external syslog. If the organization has a centralized repository (or repositories) for secure transfer of audit log files, verify each log file is configured to transfer files to the appropriate repository. Each log file must be configured separately.

[edit system syslog]
file <file name> {
    any info;
    archive size <65536..1073741824 bytes> files <1..1000> transfer-interval <5..2880 minutes> start-time "<yyyy-mm-dd.hh:mm>" archive-sites {
"URL" password "hashed PSK" } ## SECRET-DATA
}
Note: The  URL format is: <scp|sftp>://<username>@<address>/<path>. The trailing slash is omitted because Junos automatically adds that when it appends the filename.
host <external syslog address> {
    any info;
}
Note: If using secure file transfer to offload log files, the Juniper device will immediately attempt to connect with the configured protocol, address, and credentials. If successful, Junos will prompt to accept an untrusted public key. If the administrator accepts that key, Junos adds it to [edit security ssh-known-hosts]. Alternately, configure the trusted public key at [edit security ssh-known-hosts] before configuring automatic file offload.

If the device does not offload audit records onto a different system or media, this is a finding.'
  desc 'fix', 'Configure the network device to offload audit records onto a different system or media than the system being audited.

set file <file name> any info
set system syslog file <file name> any info
set system syslog file <file name> archive size <65536..1073741824 bytes>
set system syslog file <file name> archive files <1..1000>
set system syslog file <file name> archive transfer-interval <5..2880 minutes>
set system syslog file <file name> archive start-time "<yyyy-mm-dd.hh:mm>"
set system syslog file <file name> archive archive-sites "<scp|sftp>://<username>@<repository address>/<path without trailing slash (/)>" password "<PSK>"
set system syslog host <external syslog address> any info'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57389r846818_chk'
  tag severity: 'medium'
  tag gid: 'V-253937'
  tag rid: 'SV-253937r879886_rule'
  tag stig_id: 'JUEX-NM-000600'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-57340r846820_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
