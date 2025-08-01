control 'SV-254107' do
  title 'Nutanix AOS must protect log information from any type of unauthorized access.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to his or her advantage.

Application servers contain admin interfaces that allow reading and manipulation of log records. Therefore, these interfaces should not allow unfettered access to those records. Application servers also write log data to log files which are stored on the OS, so appropriate file permissions must also be used to restrict access.

Log information includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized read access.

'
  desc 'check', 'Confirm Nutanix AOS application server log files are protected from unauthorized read access.

The Nutanix AOS application server log files are owned by the Nutanix user and have a file permission of "640".

Step 1. Identify actual file name by looking at alert_manager.INFO, which is a symlink for the actual rotating file name.
$ sudo ls -al /home/nutanix/data/logs/alert_manager.INFO 
lrwxrwxrwx. 1 nutanix nutanix 75 Nov  1 17:50 /home/nutanix/data/logs/alert_manager.INFO -> alert_manager.ntnx-<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>

Step 2. Execute a stat command on the actual application server log file name.
$ sudo stat -c "%a %n" /home/nutanix/data/logs/alert_manager.ntnx-<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>
640  /home/nutanix/data/logs/alert_manager.ntnx<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>

If the output of the actual log file name is not "640", this is a finding.'
  desc 'fix', 'To configure Nutanix AOS Prism Elements application server log file permissions, run the following command:

$ sudo salt-call state.sls security/CVM/interactivenutanixCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57592r846407_chk'
  tag severity: 'medium'
  tag gid: 'V-254107'
  tag rid: 'SV-254107r846409_rule'
  tag stig_id: 'NUTX-AP-000190'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-57543r846408_fix'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
