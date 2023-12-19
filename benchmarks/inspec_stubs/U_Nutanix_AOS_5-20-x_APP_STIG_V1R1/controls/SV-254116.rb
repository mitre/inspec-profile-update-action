control 'SV-254116' do
  title 'Nutanix AOS must restrict error messages only to authorized users.'
  desc 'If the application provides too much information in error logs and administrative messages to the screen, this could lead to compromise. The structure and content of error messages need to be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements.

Application servers must protect the error messages created by the application server. All application server user accounts are used for the management of the server and the applications residing on the application server. All accounts are assigned to a certain role with corresponding access rights. The application server must restrict access to error messages so only authorized users may view them. Error messages are usually written to logs contained on the file system. The application server will usually create new log files as needed and must take steps to ensure that the proper file permissions are utilized when the log files are created.'
  desc 'check', 'The Nutanix AOS application server log files are owned by the Nutanix user and have a file permission of "640".

Step 1. Identify actual file name by looking at alert_manager.INFO, which is a symlink, the actual rotating file name.
$ sudo ls -al /home/nutanix/data/logs/alert_manager.INFO 
lrwxrwxrwx. 1 nutanix nutanix 75 Nov  1 17:50 /home/nutanix/data/logs/alert_manager.INFO -> alert_manager.ntnx-<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>

Step 2. Execute a stat command on the actual application server log file name.
$ sudo stat -c "%a %n" /home/nutanix/data/logs/alert_manager.ntnx-<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>
640  /home/nutanix/data/logs/alert_manager.ntnx<CVM_NAME>.nutanix.log.INFO.<LOG_NUMBER>

If the output of the actual log file name is not "640", this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements application server log file permissions, run the following command:

$ sudo salt-call state.sls security/CVM/interactivenutanixCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57601r846434_chk'
  tag severity: 'medium'
  tag gid: 'V-254116'
  tag rid: 'SV-254116r846436_rule'
  tag stig_id: 'NUTX-AP-000490'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-57552r846435_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
