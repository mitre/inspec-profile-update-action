control 'SV-220357' do
  title 'MarkLogic Server software, including configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application could potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens, and is threatened by, other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'Only applications required for the functioning and administration, not use of, MarkLogic should be located in the same disk directory as the MarkLogic software libraries. Review the MarkLogic software library directories /opt/MarkLogic and /var/opt/MarkLogic and note other root directories located on the same disk directory or any subdirectories.

If any non-MarkLogic software directories exist on the disk directory, examine or investigate their use. If any of the directories are used by other applications, including third-party applications that use MarkLogic, this is a finding.

At a command prompt on the MarkLogic system, run the following commands:
> ls /opt/MarkLogic

If any directories exist that are not in the list below, this is a finding.
Admin bin FlexRep include Lang Messages 
Apps Config HealthCheck Installer mlcmd Plugins
Assets Converters java lib Modules Samples

At a command prompt on the MarkLogic system, run the following commands:
> ls /var/opt/MarkLogic

If any directories exist that are not in the list below, this is a finding.
kms Lib run Stage
Forests Journals Label Logs Temp

If other software is installed in those directories and is not approved by Org Policy, this is a finding.'
  desc 'fix', 'Only applications that are required for the functioning and administration, not use of, MarkLogic should be located in the same disk directory as the MarkLogic software libraries. Review the MarkLogic software library directories /opt/MarkLogic and /var/opt/MarkLogic and note other root directories located on the same disk directory or any subdirectories.

Remove any other applications, including third-party applications that use MarkLogic that are not approved by Org Policy.

At a command prompt on the MarkLogic system, run the following commands:
If the software was installed via yum/rpm
> sudo yum remove [Software-Package-Name]
If the software was installed via unzip/untar.
> sudo rm -r [/path/to/unauthorized/software]'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22072r401522_chk'
  tag severity: 'medium'
  tag gid: 'V-220357'
  tag rid: 'SV-220357r622777_rule'
  tag stig_id: 'ML09-00-002700'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-22061r401523_fix'
  tag 'documentable'
  tag legacy: ['SV-110061', 'V-100957']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
