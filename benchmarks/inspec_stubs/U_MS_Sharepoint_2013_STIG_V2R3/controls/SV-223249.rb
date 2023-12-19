control 'SV-223249' do
  title 'SharePoint must prevent the execution of prohibited mobile code.'
  desc %q(Decisions regarding the utilization of mobile code within organizational information systems need to include evaluations that help determine the potential for the code to cause damage to the system if used maliciously.

Mobile code technologies include, for example, Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. Usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

Applications can prevent the execution of prohibited mobile code by leveraging architectures that provide a virtual execution environment sometimes referred to as a "sandbox". The mobile code is executed within this isolated environment apart from the host's indigenous operating environment that allows for mobile code capability restrictions and helps to prevent malicious code from accessing system resources and data.

Policy and procedures related to mobile code address preventing the introduction of unacceptable mobile code within the information system. The DoDI 8552.01 policy pertains to the use of mobile code technologies within DoD information systems.

The application must prevent the execution of prohibited mobile code.)
  desc 'check', 'Review the SharePoint server configuration to ensure the execution of prohibited mobile code is prevented.

Navigate to Central Administration.

Click Manage Web Applications.

For each Web Application in the Farm:
-Click on the Web Application to configure.
-Click on the drop-down box below General Settings.
-Click on General Settings in the drop down box.
-Under Browser File Handling, verify that "Strict" is selected.

If "Strict" is not selected, this is a finding.'
  desc 'fix', 'Configure SharePoint to prevent the execution of prohibited mobile code.

Navigate to Central Administration.

Click Manage Web Applications.

For each Web Application in the Farm:
-Click on the Web Application to configure.
-Click on the drop-down box below General Settings.
-Click on General Settings in the drop down box.
-Under Browser File Handling, verify that "Strict" is selected.

If "Strict" is not selected, this is a finding.

Mobile code can be further restricted to meet the policy of the organization:

Log on to a farm server hosting Central Administration.

Click Start and type SharePoint 2013 Management Shell followed by Enter.

Type $webApp = Get-SPWebApplication -Identity {URL} where {URL is the {URL} of the web application to configure.

Press Enter.

Type $webApp.AllowedInlineDownloadedMimeTypes. Remove ({mime type}) where {mime type} represents the mime type to remove (e.g., application\\x-shockwave-flash).

Press Enter.'
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24922r430807_chk'
  tag severity: 'high'
  tag gid: 'V-223249'
  tag rid: 'SV-223249r612235_rule'
  tag stig_id: 'SP13-00-000065'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-24910r430808_fix'
  tag 'documentable'
  tag legacy: ['SV-74387', 'V-59957']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
