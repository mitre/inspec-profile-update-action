control 'SV-255242' do
  title 'SSMC must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages needs to be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'To verify that SSMC is configured to prevent exfiltration of sensitive information, do the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ grep ^ssmc.management.notification.disable /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties

ssmc.management.notification.disable=false

If the command output does not print "ssmc.management.notification.disable=false", this is a finding.'
  desc 'fix', 'To configure SSMC to prevent exfiltration of sensitive information, disable all management email notifications. Execute the following steps:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Edit /opt/hpe/ssmc/ssmcbase/resources/ssmc.properties using vi editor.

3. Locate and uncomment the property "ssmc.management.notification.disable=false". Save and exit.

4. Using TUI menu option 2, restart SSMC service.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58855r869874_chk'
  tag severity: 'medium'
  tag gid: 'V-255242'
  tag rid: 'SV-255242r869876_rule'
  tag stig_id: 'SSMC-OS-010080'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-58799r869875_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
