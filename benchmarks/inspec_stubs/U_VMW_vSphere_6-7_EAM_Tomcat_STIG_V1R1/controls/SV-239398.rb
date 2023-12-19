control 'SV-239398' do
  title 'Rsyslog must be configured to monitor and ship ESX Agent Manager log files.'
  desc 'ESX Agent Manager a number of logs that must be offloaded from the originating system. This information can then be used for diagnostic, forensic, or other purposes relevant to ensuring the availability and integrity of the hosted application.

'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-services-eam.conf

Expected result:

input(type="imfile"
      File="/var/log/vmware/eam/eam.log"
      Tag="eam-main"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost_access_log*.txt"
      Tag="eam-access"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/jvm.log.std*"
      Tag="eam-stdout"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/catalina*.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost.*.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/firstboot/eam_firstboot.py*.log"
      Tag="eam-firstboot"
      Severity="info"
      Facility="local0")      File="/var/log/vmware/firstboot/eam_firstboot.py*.log"
      Tag="eam-firstboot"
      Severity="info"
      Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/vmware-syslog/stig-services-eam.conf.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile"
      File="/var/log/vmware/eam/eam.log"
      Tag="eam-main"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost_access_log*.txt"
      Tag="eam-access"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/jvm.log.std*"
      Tag="eam-stdout"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/catalina*.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/eam/web/localhost.*.log"
      Tag="eam-catalina"
      Severity="info"
      Facility="local0")
input(type="imfile"
      File="/var/log/vmware/firstboot/eam_firstboot.py*.log"
      Tag="eam-firstboot"
      Severity="info"
      Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 EAM Tomcat'
  tag check_id: 'C-42631r674686_chk'
  tag severity: 'medium'
  tag gid: 'V-239398'
  tag rid: 'SV-239398r674688_rule'
  tag stig_id: 'VCEM-67-000027'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-42590r674687_fix'
  tag satisfies: ['SRG-APP-000358-WSR-000163', 'SRG-APP-000125-WSR-000071']
  tag 'documentable'
  tag cci: ['CCI-001348', 'CCI-001851']
  tag nist: ['AU-9 (2)', 'AU-4 (1)']
end
