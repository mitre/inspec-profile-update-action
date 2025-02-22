control 'SV-239708' do
  title 'vSphere UI log files must be moved to a permanent repository in accordance with site policy.'
  desc 'vSphere UI produces a handful of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensic, or other purposes relevant to ensuring the availability and integrity of the hosted application.

'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-services-vsphere-ui.conf

Expected result:

input(type="imfile"

      File="/var/log/vmware/vsphere-ui/logs/access/localhost_access*"

      Tag="ui-access"

      Severity="info"

      Facility="local0")

input(type="imfile"

      File="/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*"

      Tag="ui-runtime"

      Severity="info"

      Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vmware-syslog/stig-services-vsphere-ui.conf.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/access/localhost_access*"
      Tag="ui-access"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/vsphere-ui/logs/vsphere-ui-runtime*"
      Tag="ui-runtime"
      Severity="info"
      Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42941r679228_chk'
  tag severity: 'medium'
  tag gid: 'V-239708'
  tag rid: 'SV-239708r679230_rule'
  tag stig_id: 'VCUI-67-000027'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-42900r679229_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000108-WSR-000166', 'SRG-APP-000125-WSR-000071']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-001348', 'CCI-001851']
  tag nist: ['AU-5 a', 'AU-9 (2)', 'AU-4 (1)']
end
