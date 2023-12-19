control 'SV-239768' do
  title 'Rsyslog must be configured to monitor and ship vSphere Client log files.'
  desc 'The vSphere Client produces a handful of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensics, or other purposes relevant to ensuring the availability and integrity of the hosted application.'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-vsphere-client.conf

Expected result:

input(type="imfile"
      File="/var/log/vmware/vsphere-client/logs/access/localhost_access*"
      Tag="client-access"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/vsphere-client/logs/vsphere-client-runtime*"
      Tag="client-runtime"
      Severity="info"
      Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware-syslog/stig-vsphere-client.conf.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile"
      File="/var/log/vmware/vsphere-client/logs/access/localhost_access*"
      Tag="client-access"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/vsphere-client/logs/vsphere-client-runtime*"
      Tag="client-runtime"
      Severity="info"
      Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-43001r679529_chk'
  tag severity: 'medium'
  tag gid: 'V-239768'
  tag rid: 'SV-239768r679531_rule'
  tag stig_id: 'VCFL-67-000027'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-42960r679530_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
