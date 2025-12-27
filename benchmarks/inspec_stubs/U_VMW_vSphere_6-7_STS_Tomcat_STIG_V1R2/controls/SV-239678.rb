control 'SV-239678' do
  title 'Rsyslog must be configured to monitor and ship Security Token Service log files.'
  desc 'The Security Token Service produces a number of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensics, or other purposes relevant to ensuring the availability and integrity of the hosted application.

'
  desc 'check', 'Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-services-sso.conf

Expected result:

input(type="imfile"
      File="/var/log/vmware/sso/*.log"
      Tag="vmidentity"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.*"
      Tag="sts-runtime"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Connect to the PSC, whether external or embedded.

Navigate to and open /etc/vmware-syslog/stig-services-sso.conf.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile"
      File="/var/log/vmware/sso/*.log"
      Tag="vmidentity"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/sso/sts-runtime.log.*"
      Tag="sts-runtime"
      PersistStateInterval="200"
      Severity="info"
      Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42911r816757_chk'
  tag severity: 'medium'
  tag gid: 'V-239678'
  tag rid: 'SV-239678r816759_rule'
  tag stig_id: 'VCST-67-000027'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-42870r816758_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000125-WSR-000071']
  tag 'documentable'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']
end
